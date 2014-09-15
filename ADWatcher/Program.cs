using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.IO;
using log4net;
using System.Data.SQLite;

namespace ADWatcher
{
    public class ADSearcher
    {
        static internal readonly ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        internal PrincipalContext pctx = new PrincipalContext(ContextType.Domain);

        public void reconnect()
        {
            PrincipalContext oldPctx = pctx;
            PrincipalContext newPctx = new PrincipalContext(ContextType.Domain);
            pctx = newPctx;

            try
            {
                oldPctx.Dispose();
            }
            catch (Exception e)
            {
                logger.Warn("古い接続の切断に失敗しました．", e);
            }
        }

        public bool isExist(string samAccountName, bool isRetry = false)
        {
            try
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(pctx, IdentityType.SamAccountName, samAccountName);

                if (user != null && user.Sid != null)
                {
                    return true;
                }

                return false;
            }
            catch (Exception)
            {
                if (isRetry)
                {
                    throw;
                }
                else
                {
                    reconnect();
                    return isExist(samAccountName, true);
                }
            }
        }
    }

    public class ChangeNotifier : IDisposable
    {
        static internal readonly ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        
        LdapConnection _connection;
        HashSet<IAsyncResult> _results = new HashSet<IAsyncResult>();

        public ChangeNotifier(LdapConnection connection)
        {
            _connection = connection;
            _connection.AutoBind = true;
        }

        public void Register(string dn, string filter, System.DirectoryServices.Protocols.SearchScope scope)
        {
            SearchRequest request = new SearchRequest(
                dn, //root the search here
                filter, //very inclusive
                scope, //any scope works
                null //we are interested in all attributes
                );

            //register our search
            request.Controls.Add(new DirectoryNotificationControl());

            //we will send this async and register our callback
            //note how we would like to have partial results
            IAsyncResult result = _connection.BeginSendRequest(
                request,
                TimeSpan.FromDays(1), //set timeout to a day...
                PartialResultProcessing.ReturnPartialResultsAndNotifyCallback,
                Notify,
                request
                );

            //store the hash for disposal later
            _results.Add(result);
        }

        private void Notify(IAsyncResult result)
        {
            //since our search is long running, we don't want to use EndSendRequest
             PartialResultsCollection prc = _connection.GetPartialResults(result);

            foreach (SearchResultEntry entry in prc)
            {
                OnObjectChanged(new ObjectChangedEventArgs(entry));
            }
        }

        private void OnObjectChanged(ObjectChangedEventArgs args)
        {
            if (ObjectChanged != null)
            {
                ObjectChanged(this, args);
            }
        }

        public event EventHandler<ObjectChangedEventArgs> ObjectChanged;

        #region IDisposable Members

        public void Dispose()
        {
            foreach (var result in _results)
            {
                //end each async search
                _connection.Abort(result);
            }
        }

        #endregion
    }

    public class ObjectChangedEventArgs : EventArgs
    {
        public ObjectChangedEventArgs(SearchResultEntry entry)
        {
            Result = entry;
        }

        public SearchResultEntry Result { get; set; }
    }

    class HistoryManager
    {
        public static string dbFile = @"data\ADHistory.db";
        internal static SQLiteConnection connection;

        public static void connect()
        {
            if (connection == null)
            {
                lock (typeof(HistoryManager))
                {
                    if (connection == null)
                    {
                        connection = new SQLiteConnection(@"Data Source=" + dbFile);
                        connection.Open();
                    }
                }
            }
        }

        public static void initialize()
        {
            connect();

            using (SQLiteCommand command = connection.CreateCommand())
            {
                command.CommandText = @"CREATE TABLE  IF NOT EXISTS ADUserFlags(samAccountName char(255) PRIMARY KEY, IsCreated bool, CreatedDate timestamp)";
                command.ExecuteNonQuery();
            }
        }


        public static bool isExist(string samAccountName)
        {
            using (SQLiteCommand command = connection.CreateCommand())
            {
                command.CommandText = @"SELECT COUNT(samAccountName) FROM ADUserFlags WHERE samAccountName = ?";
                command.Parameters.Add("samAccountName", System.Data.DbType.String, 255);
                command.Prepare();

                command.Parameters[0].Value = samAccountName;

                return "0" != command.ExecuteScalar().ToString();
            }
        }

        public static bool add(string samAccountName, bool isCreated)
        {
            using (SQLiteCommand command = connection.CreateCommand())
            {
                command.CommandText = @"INSERT OR REPLACE INTO ADUserFlags (samAccountName, IsCreated, CreatedDate) VALUES (?, ?, datetime('now'))";
                command.Parameters.Add("samAccountName", System.Data.DbType.String, 255);
                command.Parameters.Add("IsCreated", System.Data.DbType.String, 255);
                command.Prepare();

                command.Parameters[0].Value = samAccountName;
                command.Parameters[1].Value = isCreated;

                return 0 != command.ExecuteNonQuery();
            }
        }
    }

    class Program
    {
        static string ldapFilter = @"(objectclass=*)";
        static internal readonly ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        static void Main(string[] args)
        {
            logger.Info("Startup");

            if (! File.Exists(HistoryManager.dbFile))
            {
                firstRun();
            }

            HistoryManager.connect();

            string domain = Environment.ExpandEnvironmentVariables("%USERDNSDOMAIN%");
            string domainDN = @"DC=" + domain.Replace(@".", @",DC=");

            try
            {
                logger.Info("ドメインコントローラーへの接続を試行してます．");
                using (LdapConnection connect = new LdapConnection(domain))
                using (ChangeNotifier notifier = new ChangeNotifier(connect))
                {
                    //register some objects for notifications (limit 5)
                    notifier.Register(domainDN, ldapFilter,
                        System.DirectoryServices.Protocols.SearchScope.Subtree);

                    notifier.ObjectChanged += new EventHandler<ObjectChangedEventArgs>(notifier_ObjectChanged);

                    logger.Info("ドメインコントローラーへの接続に成功しました．変更監視を開始します．");

                    Console.ReadLine();
                }
            }
            finally
            {
                logger.Info("Shutdown");
            }
        }


        /// <summary>
        /// 初回起動向けに，全てのユーザーアカウントに対して，ディレクトリ作成済みフラグを付けます．
        /// </summary>
        static void firstRun()
        {
            logger.Info("初回起動のため，データベース初期化を行います．");

            HistoryManager.connect();
            HistoryManager.initialize();

            DirectorySearcher src = new DirectorySearcher("(objectClass=User)");
            foreach (SearchResult result in src.FindAll())
            {
                HistoryManager.add(result.Properties["samAccountName"].OfType<string>().First(), false);
            }

            logger.Info("データベース初期化が完了しました．");
        }

        static ADSearcher searcher = new ADSearcher();

        static void notifier_ObjectChanged(object sender, ObjectChangedEventArgs e)
        {
            SearchResultEntry result = e.Result;

            logger.Info("Changed:" + result.DistinguishedName);

            if (! isUserAccount(result))
            {
                logger.Info("Not a user Account");
                return;
            }

            if (logger.IsDebugEnabled)
            {
                foreach (string attrib in e.Result.Attributes.AttributeNames)
                {
                    foreach (var item in e.Result.Attributes[attrib].GetValues(typeof(string)))
                    {
                        logger.DebugFormat("\t{0}: {1}", attrib, item);
                    }
                }
            }

            var samAccountName = result.Attributes["samAccountName"].GetValues(typeof(string)).Cast<string>().First<string>();

            /// ユーザーを作成しようとしたが，必須項目が入力されていなかったり，
            /// パスワードの要件が満たされなかった場合，変更イベントは送信されるが，
            /// その後アカウントが存在しない状況が発生する．
            /// そういった状況を避けるため，30秒後に再度クエリを実行し，ユーザーアカウントが取得できることを確認する．
            System.Threading.Thread.Sleep(30000);
            if (!searcher.isExist(samAccountName))
            {
                logger.InfoFormat(@"{0} の変更要求を受け取りましたが，ディレクトリ上に見つかりませんでした．", samAccountName);
                return;
            }


            ///
            if (HistoryManager.isExist(samAccountName))
            {
                logger.Info(samAccountName + @" は作成済みキャッシュにあります．");
                return;
            }

            try
            {
                invokeCommand(samAccountName);
                HistoryManager.add(samAccountName, true);
            }
            catch (Exception exception)
            {
                logger.Error("コマンド実行エラー", exception);
            }
        }


        static bool isUserAccount(SearchResultEntry entry)
        {
            if (!entry.Attributes.Contains("objectclass"))
            {
                return false;
            }

            var objectClass = entry.Attributes["objectclass"].GetValues(typeof(string));

            logger.Debug(objectClass);

            if (! objectClass.Contains("user"))
            {
                return false;
            }

            return true;
        }


        static bool invokeCommand(string samAccountName)
        {

            return true;
        }
    }
}
