using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificationLib
{
    public class CertLib
    {
        /// <summary>
        /// Using certification to sign some content
        /// </summary>
        /// <param name="storeName">System.Security.Cryptography.X509Certificates.StoreName</param>
        /// <param name="storeLocation">System.Security.Cryptography.X509Certificates.StoreLocation</param>
        /// <param name="certSubject">Certification subject name</param>
        /// <param name="content">The content you want to sign</param>
        /// <returns></returns>
        public string Sign(StoreName storeName,StoreLocation storeLocation,string certSubject,string content)
        {
            if(string.IsNullOrEmpty(certSubject) || string.IsNullOrEmpty(content))
            {
                throw new ArgumentException();
            }
            X509Store store = new X509Store(storeName, storeLocation);
            X509Certificate2Collection cols = store.Certificates;
            foreach (X509Certificate2 item in cols)
            {
                if(item.Subject==certSubject)
                {
                    RSACryptoServiceProvider privateKeyProvider = new RSACryptoServiceProvider();
                    privateKeyProvider.FromXmlString(item.PrivateKey.ToXmlString(true));
                    return Sign(privateKeyProvider, content);
                }
            }
            return null;
        }

        private string Sign(RSACryptoServiceProvider provider,string content)
        {
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(content);
            SHA1Managed sha1 = new SHA1Managed();
            byte[] rgbHash = sha1.ComputeHash(data);
            byte [] result = provider.SignHash(rgbHash, CryptoConfig.MapNameToOID("SHA1"));
            return Convert.ToBase64String(result);
        }

    }
}
