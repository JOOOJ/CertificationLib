using System;
using System.Text;
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
        public string Sign(StoreName storeName, StoreLocation storeLocation, string certSubject, string content)
        {
            if (string.IsNullOrEmpty(certSubject) || string.IsNullOrEmpty(content))
            {
                throw new ArgumentException();
            }
            X509Store store = new X509Store(storeName, storeLocation);
            X509Certificate2Collection cols = store.Certificates;
            foreach (X509Certificate2 item in cols)
            {
                if (item.Subject == certSubject)
                {
                    RSACryptoServiceProvider privateKeyProvider = new RSACryptoServiceProvider();
                    privateKeyProvider.FromXmlString(item.PrivateKey.ToXmlString(true));
                    return Sign(privateKeyProvider, content);
                }
            }
            return null;
        }

        /// <summary>
        /// Verify the content is signed with this certification
        /// </summary>
        /// <param name="storeName">System.Security.Cryptography.X509Certificates.StoreName</param>
        /// <param name="storeLocation">System.Security.Cryptography.X509Certificates.StoreLocation</param>
        /// <param name="certSubject">Certification subject name</param>
        /// <param name="content">The content you want to sign</param>
        /// <param name="signContent">The sign result</param>
        /// <returns></returns>
        public bool Verify(StoreName storeName, StoreLocation storeLocation, string certSubject, string content, string signContent)
        {
            if (string.IsNullOrEmpty(certSubject) || string.IsNullOrEmpty(content) || string.IsNullOrEmpty(signContent))
            {
                throw new ArgumentException();
            }
            X509Store store = new X509Store(storeName, storeLocation);
            X509Certificate2Collection cols = store.Certificates;
            foreach (X509Certificate2 item in cols)
            {
                if (item.Subject == certSubject)
                {
                    RSACryptoServiceProvider publicKeyProvider = new RSACryptoServiceProvider();
                    publicKeyProvider.FromXmlString(item.PublicKey.Key.ToXmlString(false));
                    return Verify(publicKeyProvider, content, signContent);
                }
            }
            return false;
        }

        /// <summary>
        /// Encrypt content
        /// </summary>
        /// <param name="storeName">System.Security.Cryptography.X509Certificates.StoreName</param>
        /// <param name="storeLocation">System.Security.Cryptography.X509Certificates.StoreLocation</param>
        /// <param name="certSubject">Certification subject name</param>
        /// <param name="content">The content you want to sign</param>
        /// <returns>Encrypt content result</returns>
        public string RSAEncrypt(StoreName storeName, StoreLocation storeLocation, string certSubject, string content)
        {
            if (string.IsNullOrEmpty(certSubject) || string.IsNullOrEmpty(content))
            {
                throw new ArgumentException();
            }
            X509Store store = new X509Store(storeName, storeLocation);
            X509Certificate2Collection cols = store.Certificates;
            foreach (X509Certificate2 item in cols)
            {
                if (item.Subject == certSubject)
                {
                    RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                    provider.FromXmlString(item.PrivateKey.ToXmlString(true));
                    byte[] rgb = new UnicodeEncoding().GetBytes(content);
                    byte[] result = provider.Encrypt(rgb, false);
                    return Convert.ToBase64String(result);
                }
            }
            return null;
        }

        /// <summary>
        /// Decrypt content
        /// </summary>
        /// <param name="storeName">System.Security.Cryptography.X509Certificates.StoreName</param>
        /// <param name="storeLocation">System.Security.Cryptography.X509Certificates.StoreLocation</param>
        /// <param name="certSubject">Certification subject name</param>
        /// <param name="encryptContent">The encrypt content</param>
        /// <returns>Decrypt result</returns>
        public string RSADecrypt(StoreName storeName, StoreLocation storeLocation, string certSubject, string encryptContent)
        {
            if (string.IsNullOrEmpty(certSubject) || string.IsNullOrEmpty(encryptContent))
            {
                throw new ArgumentException();
            }
            X509Store store = new X509Store(storeName, storeLocation);
            X509Certificate2Collection cols = store.Certificates;
            foreach (X509Certificate2 item in cols)
            {
                if (item.Subject == certSubject)
                {
                    RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                    provider.FromXmlString(item.PublicKey.Key.ToXmlString(false));
                    byte[] rgb = new UnicodeEncoding().GetBytes(encryptContent);
                    byte[] result = provider.Decrypt(rgb, true);
                    return Convert.ToBase64String(result);
                }
            }
            return null;
        }

        private string Sign(RSACryptoServiceProvider provider, string content)
        {
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(content);
            SHA1Managed sha1 = new SHA1Managed();
            byte[] rgbHash = sha1.ComputeHash(data);
            byte[] result = provider.SignHash(rgbHash, CryptoConfig.MapNameToOID("SHA1"));
            return Convert.ToBase64String(result);
        }

        private bool Verify(RSACryptoServiceProvider provider, string content, string signContent)
        {
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(content);
            SHA1Managed sha1 = new SHA1Managed();
            byte[] rgbHash = sha1.ComputeHash(data);
            return provider.VerifyHash(rgbHash, CryptoConfig.MapNameToOID("SHA1"), Convert.FromBase64String(signContent));
        }

    }
}
