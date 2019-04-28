using Microsoft.Win32;
using System;
using System.Security.AccessControl;
using System.Security.Principal;
namespace WindowsFormsApp10
{ // By Bashar Bachir => https://protection-tips.com/vb/ 
// ver 1 > Stop Registry Edit , ver 2 > Stop Powershell Commands
// this is ver 1
    public class Program
    {
        public static void Main()
        {
            Undeletable(@"SOFTWARE\Policies\Microsoft\Windows Defender");
        }
        static void Undeletable(string key)
        {
            var account = new SecurityIdentifier(WellKnownSidType.WorldSid, null).Translate(typeof(NTAccount)) as NTAccount;
            using (var rk = Registry.LocalMachine.OpenSubKey(key, true))
            {
                var rs = new RegistrySecurity();
                if (account != null)
                {
                    rs.AddAccessRule(new RegistryAccessRule(account.ToString(), RegistryRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
                        AccessControlType.Deny));
                }
                rk?.SetAccessControl(rs);
            }
        }
    }
}
