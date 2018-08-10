

#region Using directives
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
#endregion

namespace SuperNova.Security.Cryptography.CryptographySupports
{
    /// <summary>
    /// OPEN SSL wrapper
    /// </summary>
    public class CertificateManager
    {
        /// <summary>
        /// Converts PEM to DER
        /// </summary>
        /// <param name="payload">The payload</param>
        /// <returns>data</returns>
        public async static Task<string> ConvertPemToDerAsync(FormatConversionRequestPayload payload)
        {
            var outputFileName = "certificate.der";
            var keyFileName = $"userInput.{payload.InputFormat.ToString().ToLowerInvariant()}";
            DeleteFileIfExists(keyFileName);

            await System.IO.File.WriteAllTextAsync(keyFileName, payload.Base64FileContent);

            var command = $"openssl x509 -outform der -in {keyFileName} -out {outputFileName}";

            var logs = ExecuteOpenSsl(command);

            return await System.IO.File.ReadAllTextAsync(outputFileName);
        }

        /// <summary>
        /// Converts pem
        /// </summary>
        /// <param name="payload">The payload data</param>
        /// <returns>Data</returns>
        public async static Task<string> ConvertToPemAsync(FormatConversionRequestPayload payload)
        {
            var outputFileName = "output.pem";
            var keyFileName = $"userInput.{payload.InputFormat.ToString().ToLowerInvariant()}";
            DeleteFileIfExists(keyFileName);

            await System.IO.File.WriteAllTextAsync(keyFileName, payload.Base64FileContent);

            var command = $"openssl x509 -inform der -in {keyFileName} -out {outputFileName}";

            var logs = ExecuteOpenSsl(command);

            return await System.IO.File.ReadAllTextAsync(outputFileName);
        }

        /// <summary>
        /// Generates CSR
        /// </summary>
        /// <param name="payload">Payload data</param>
        /// <returns>CSR</returns>
        public async static Task<CsrResponse> GenerateCSRAsync(CsrRequestPayload payload)
        {
            var response = new CsrResponse();

            var name = payload.Organization.ToLowerInvariant();
            var keyFileName = $"{name}.key";
            var csrFileName = $"{name}.csr";

            DeleteFileIfExists(keyFileName);
            DeleteFileIfExists(csrFileName);

            var subject = $"/C={payload.Country}/ST={payload.State}/L={payload.Location}/O={payload.Organization}/OU={payload.OrganizationalUnit}/CN={payload.CommonName}";
            var command = $" req -nodes -newkey rsa:4096 -keyout \"{keyFileName}\" -out \"{csrFileName}\" -subj \"{subject}\"";

            var logs = ExecuteOpenSsl(command);
            response.Logs = logs.ToString();

            if (System.IO.File.Exists(csrFileName))
            {
                var text = new StringBuilder();
                text.AppendLine(await System.IO.File.ReadAllTextAsync(csrFileName));
                text.AppendLine(await System.IO.File.ReadAllTextAsync(keyFileName));

                response.CsrText = text.ToString();
            }
            return response;
        }

        /// <summary>
        /// Generate PFX
        /// </summary>
        /// <param name="payload">payload</param>
        /// <returns>The cotnent</returns>
        public async static Task<string> GeneratePfxAsync(ConvertToPfxPayload payload)
        {
            var outputFileName = "certificate.pfx";

            var keyFile = $"{Guid.NewGuid().ToString("N")}.key";
            var crtFile = $"{Guid.NewGuid().ToString("N")}.crt";
            var caCert = $"{Guid.NewGuid().ToString("N")}.crt";


            DeleteFileIfExists(keyFile);
            DeleteFileIfExists(crtFile);
            DeleteFileIfExists(caCert);

            await File.WriteAllTextAsync(keyFile, payload.PrivateKey);
            await File.WriteAllTextAsync(crtFile, payload.CertifcateData);
            await File.WriteAllTextAsync(caCert, payload.CertificateAuthorityData);

            var command = $"pkcs12 -export -out {outputFileName} -inkey {keyFile} -in {crtFile} -certfile {caCert}";

            var logs = ExecuteOpenSsl(command);

            return await System.IO.File.ReadAllTextAsync(outputFileName);
        }


        private static StringBuilder ExecuteOpenSsl(string command)
        {
            var logs = new StringBuilder();
            var executableName = "openssl";
            var processInfo = new ProcessStartInfo(executableName)
            {
                Arguments = command,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            var process = Process.Start(processInfo);
            while (!process.StandardOutput.EndOfStream)
            {
                logs.AppendLine(process.StandardOutput.ReadLine());
            }
            logs.AppendLine(process.StandardError.ReadToEnd());
            return logs;
        }

        private static void DeleteFileIfExists(string keyFileName)
        {
            if (System.IO.File.Exists(keyFileName))
            {
                System.IO.File.Delete(keyFileName);
            }
        }
    }
}
