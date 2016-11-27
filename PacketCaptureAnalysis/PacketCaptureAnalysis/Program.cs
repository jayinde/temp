using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Reflection;

namespace PacketCaptureAnalysis
{
    class Program
    {
        static void Main(string[] args)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "a\\";
            string appBasePath = @"C:\website\PacketCaptureAnalysis\PacketCaptureAnalysis\";

            /// This is just Analysis for Network => http.log
            /// Base on https://www.bro.org/sphinx/script-reference/log-files.html
            /// 
            /// 1. Get all directory name into array of string
            /// 2. Then get all http.log file in each directory
            /// 3. Http Object class is built from first file (line 7 = field name and line 8 = datatype)  
            /// 4. Get data (line 9 downwards) from all files into a list of object
            /// 
            IEnumerable<string> directories = Directory.EnumerateDirectories(path);

            // Build the object base on the file header (field name and datatype)
            string httLogObj = appBasePath + "httpLog.cs";
            // If object not exist create object
            if (!File.Exists(httLogObj))
            {
                string oneDir = directories.ToArray()[0];
                var fl_log = Directory.GetFiles(oneDir, "*http.log")[0];
                string[] rows = File.ReadAllLines(fl_log);
                string[] arrFileNames = rows[6].Split("\t".ToCharArray());
                string[] arrDataType = rows[7].Split("\t".ToCharArray());
                int debug1 = arrFileNames.Length;
                StringBuilder objSb = new StringBuilder();
                objSb.AppendLine($"public class httpLog");
                objSb.AppendLine("{");
                for (int i = 0; i < arrFileNames.Length; i++)
                {
                    if (i > 0)
                    {
                        if (arrDataType[i].Contains("count") && !arrFileNames[i].Contains("info_code"))
                        {
                            objSb.AppendLine($"public int {arrFileNames[i].Replace('.', '_')} {{ get; set; }}");
                        }
                        else if (arrDataType[i].Contains("port"))
                        {
                            objSb.AppendLine($"public int {arrFileNames[i].Replace('.', '_')} {{ get; set; }}");
                        }
                        else
                        {
                            objSb.AppendLine($"public string {arrFileNames[i].Replace('.', '_')} {{ get; set; }}");
                        }
                    }
                }
                objSb.AppendLine("}");
                string obj = objSb.ToString();
                File.WriteAllText(httLogObj, obj);
            }

            // Read all http log file into list of httpLog object
            List<httpLog> lstHttpLog = new List<httpLog>();
            foreach (string dr in directories)
            {
                var fl_log = Directory.GetFiles(dr, "*http.log")[0];
                string[] rows = File.ReadAllLines(fl_log);
                for (int i = 0; i <= rows.Length - 1; i++)
                {
                    if (i > 7 && !string.IsNullOrWhiteSpace(rows[i][0].ToString()) && !rows[i].Contains("#close"))
                    {
                        string row = rows[i];
                        lstHttpLog.Add(row.ToHttpLog());
                    }
                }
            }

            // Analysis begin
           
            Console.WriteLine("\n################## Unique Origin IP addresses #########################");
            var idorigip = lstHttpLog.Select(x => x.id_orig_h).Distinct();
            Console.WriteLine($"Total unique IP addresses: {idorigip.Count()}");
            foreach (var x in idorigip)
            {
                Console.WriteLine($"IP address: {x}");
            }

            Console.WriteLine("\n################## Unique Respondent IP addresses #########################");
            var idrespip = lstHttpLog.Select(x => x.id_resp_h).Distinct();
            Console.WriteLine($"Total respondent IP addresses: {idrespip.Count()}");
            foreach (var x in idrespip)
            {
                Console.WriteLine($"IP address: {x}");
            }

            Console.WriteLine("\n################## Most active IP address #########################");
            var mostActiveIp = lstHttpLog
                .GroupBy(x => x.id_orig_h)
                .Select(group => new { ip = group.Key, count = group.Count() })
                .OrderByDescending(x => x.count)
                .FirstOrDefault();
            Console.WriteLine($"IP address: {mostActiveIp.ip} total: {mostActiveIp.count}");

            Console.WriteLine("\n################## Most Common Domain #########################");
            var mostDomain = lstHttpLog
                .GroupBy(x => x.host)
                .Select(group => new { host = group.Key, count = group.Count() })
                .OrderByDescending(x => x.count)
                .FirstOrDefault();
            Console.WriteLine($"IP address: {mostDomain.host} total: {mostDomain.count}");

            Console.WriteLine("\n################## Least Common Domain #########################");
            var leastDomain = lstHttpLog
                .GroupBy(x => x.host)
                .Select(group => new { host = group.Key, count = group.Count() })
                .FirstOrDefault();
            Console.WriteLine($"\nIP address: {leastDomain.host} total: {leastDomain.count}");
            
            Console.WriteLine($"\nTotal http log: {lstHttpLog.Count}");

            Console.WriteLine("################## Packet Capture Analysis #########################");

            Console.ReadKey();
        }
    }

    public static class HttpLogExtension
    {
        public static httpLog ToHttpLog(this string row)
        {
            string[] colmn = row.Split("\t".ToCharArray());

            httpLog entity = new httpLog
            {
                ts = colmn[0],
                uid = colmn[1],
                id_orig_h = colmn[2],
                id_orig_p = Convert.ToInt32(colmn[3]),
                id_resp_h = colmn[4],
                id_resp_p = Convert.ToInt32(colmn[5]),
                trans_depth = Convert.ToInt32(colmn[6]),
                method = colmn[7],
                host = colmn[8],
                uri = colmn[9],
                referrer = colmn[10],
                user_agent = colmn[11],
                request_body_len = Convert.ToInt32(colmn[12]),
                response_body_len = Convert.ToInt32(colmn[13]),
                status_code = colmn[14] == "-" ? 0 : Convert.ToInt32(colmn[14]),
                status_msg = colmn[15],
                info_code = colmn[16],
                info_msg = colmn[17],
                filename = colmn[18],
                tags = colmn[19],
                username = colmn[20],
                password = colmn[21],
                proxied = colmn[22],
                orig_fuids = colmn[23],
                orig_mime_types = colmn[24],
                resp_fuids = colmn[25],
                resp_mime_types = colmn[26]
            };
            return entity;
        }
    }
}
