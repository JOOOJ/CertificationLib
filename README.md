# Welcome to the CertificationLib wiki!
The project is an C# dll project which can provide e-signature, verify e-signature, encrypt and decrypt.
## How to create self-certification to test
There are two ways to create self-certification, one is makecert.exe, another is powershell function "New-SelfSignedCertificate". Please refer: https://msdn.microsoft.com/en-us/library/windows/desktop/aa386968(v=vs.85).aspx
## How to use the API
Each api need parameters System.Security.Cryptography.X509Certificates.StoreName, System.Security.Cryptography.X509Certificates.StoreLocation and certSubject. StoreLocation is the location which the certification installs in, only two locations we could choose. One is current user and another is local machine. There are 8 StoreNames. If we create self-certification for test, the store name is my, and we can find  the certificate in the Personal folder. 
![](https://github.com/JOOOJ/CertificationLib/blob/master/1.JPG)

certSubject is the certificate subject, we could find the value under this certificate details.
![](https://github.com/JOOOJ/CertificationLib/blob/master/2.JPG)

We can find the subject is "CN=Microsoft Root Authority, OU=Microsoft Corporation, OU=Copyright (c) 1997 Mic
rosoft Corp."
