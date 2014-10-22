using System;
using System.Globalization;
using System.Text;

namespace Katrina
{
    public class Offsets
    {
        public static int build;

        public static int Send_ds;
        public static int Recv_ds;

        public static int Send_2;
        public static int Recive;
        public static int Locale;

        public static void Load(int build)
        {
            Offsets.build = build;

            Send_ds = GetIntValue("send_ds");
            Recv_ds = GetIntValue("recv_ds");
            Send_2  = GetIntValue("send_2");
            Recive  = GetIntValue("recive");
            Locale  = GetIntValue("locale");

            if (Recv_ds == 0 || Send_ds == 0)
                throw new Exception("Can't load offsets for build " + build);
        }

        static int GetIntValue(string key)
        {
            var strval = new StringBuilder();
            WinApi.GetPrivateProfileString(build.ToString(), key, "0", strval, 20, Environment.CurrentDirectory + "\\offsets.ini");
            var val = strval.ToString();

            int result;

            if (val.StartsWith("0x")
                && int.TryParse(val.Substring(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out result))
                return result;
            else if (int.TryParse(val, out result))
                return result;
            else
                return 0;
        }
    }
}
