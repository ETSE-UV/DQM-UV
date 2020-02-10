/* 
 * Author: Juan Antonio De Rus Arance.
    This script provides network metrics and a trace of packets with qualities and several information when using mpeg-dash protocol.

   POWERSHELL 3.0 MUST BE INSTALLED. And a refence to System.Management.Automation.dll must be included. (This DLL is normally on <<C:\Program Files (x86)\Reference Assemblies\Microsoft\WindowsPowerShell\3.0>>)
   TSHARK 3.0.1 or later(a tool from wireshark) must be installed.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Text.RegularExpressions;


//inports for POWERSHELL
using System.Management.Automation;
using System.Net;
using System.Xml;
using System.Globalization;

namespace NetworkData
{
    class videoSegmentInfo //class to store video segments information from mpd
    {
        public string id;
        public string width;
        public string height;
        public string bandwidth;
        public string codecs;
        public string frameRate;

        public videoSegmentInfo(string id, string width, string height, string bandwidth, string codecs, string frameRate)
        {
            this.id = id;
            this.width = width;
            this.height = height;
            this.bandwidth = bandwidth;
            this.codecs = codecs;
            this.frameRate = frameRate;
        }
        public string print()
        {
            return ("\t\t,id=\"" + id + "\",width =\"" + width + "\",height=\"" + height + "\",bandwidth=\"" + bandwidth + "\",codecs=\"" + codecs + "\",frameRate=\"" + frameRate+ "\"");
        }
        public string printConsole()
        {
            return ("\t\t,id=\"" + id + "\",width =\"" + width + "\",height=\"" + height + "\",bandwidth=\"" + bandwidth + "\",codecs=\"" + codecs + "\",frameRate=\"" + frameRate + "\"");
        }
    }

    class audioSegmentInfo //class to store audio segments information from mpd
    {
        public string id;
        public string audioSamplingRate;
        public string bandwidth;
        public string codecs;

        public audioSegmentInfo(string id, string audioSamplingRate, string bandwidth, string codecs)
        {
            this.id = id;
            this.bandwidth = bandwidth;
            this.codecs = codecs;
            this.audioSamplingRate = audioSamplingRate;
        }
        public string print()
        {
            return ("\t\t,id=\"" + id + "\",audioSamplingRate=\"" + audioSamplingRate + "\",bandwidth=\"" + bandwidth + "\",codecs=\"" + codecs+ "\"");
        }
        public string printConsole()
        {
            return ("\t\t,id=\"" + id + "\",audioSamplingRate=\"" + audioSamplingRate + "\",bandwidth=\"" + bandwidth + "\",codecs=\"" + codecs + "\"");
        }
    }

    class Program
    {
        static void Main()
        {
            DirectoryInfo di_aux = Directory.CreateDirectory("logs");
            DirectoryInfo di = Directory.CreateDirectory("logs/" + DateTime.Now.ToString("yyyy_MM_dd"));
            string path = di_aux.ToString() + '/' + di.ToString() + '/' + DateTime.Now.ToString("HH_mm_ss") + "capture.txt";
            string pathFinalVideoTrace = di_aux.ToString() + '/' + di.ToString() + '/' + DateTime.Now.ToString("HH_mm_ss") + "_VideoTrace.txt";
            string pathFinalAudioTrace = di_aux.ToString() + '/' + di.ToString() + '/' + DateTime.Now.ToString("HH_mm_ss") + "_AudioTrace.txt";
            string pathMPD = di_aux.ToString() + '/' + di.ToString() + '/' + DateTime.Now.ToString("HH_mm_ss") + ".mpd";

            StreamWriter output = new StreamWriter(path);
            string process_name = "Unity";

            bool browser = false;
            bool useURL = false;
            bool auxbool = false;
            string aux;
            string route_TShark = "D:/Archivos de programa (X86)/Wireshark/TShark.exe";
            
            int interface_TShark = 3;
            int duration_TShark = 30;
            int timeInterval_TShark = 0;

            string response_TShark;
            string response_NetStat;

            string[] linesNetstat;
            string[] tokensNetstat;
            string ipFilter = "";
            string writeToFile = "";
            string captureFile = "";
            string readFile = " \"" + System.IO.Directory.GetCurrentDirectory() + "\\capture.pcapng\" ";
            captureFile = readFile;
            writeToFile = " -w ";
            string URL = "http://84.88.32.46/mtails/resources/MTAILS/Tears_of_steel_TV/stream.mpd";


            //Start of Script
            Console.WriteLine("***********************************");
            Console.WriteLine("Network Usage Script Initiated");
            Console.WriteLine("***********************************");

            string input;

            //Ask route to TShark.exe
            StreamReader RouteReader;
            String routeLine;
            try
            {
                RouteReader = new StreamReader("TSharkRoute.txt");
                if ((routeLine = RouteReader.ReadLine()) != null)
                    route_TShark = routeLine;
            }
            catch { }
            do
            {
                Console.WriteLine("Route to TShark.exe is: <<" + route_TShark + ">>? Y/N");
                input = Console.ReadLine();
                if (input == "N" || input == "n")
                {
                    Console.WriteLine("Write routes to TShark.exe:");
                    process_name = Console.ReadLine();
                }
                else
                    break;
            } while (true);

            //Show and choose interfaces
            Console.WriteLine("These are the available interfaces to capture traffic: (Incase there appears only UsbCap, run <<sc start npcap>> on console");

            Process tshark = new Process();
            tshark.StartInfo.FileName = route_TShark;
            tshark.StartInfo.Arguments = "-D";
            tshark.StartInfo.CreateNoWindow = false;
            tshark.StartInfo.UseShellExecute = false;
            tshark.StartInfo.RedirectStandardOutput = true;
            tshark.Start();
            Console.WriteLine(tshark.StandardOutput.ReadToEnd());
            tshark.WaitForExit();


            Console.WriteLine("Chose the number of the desired interface: ");
            interface_TShark = Convert.ToInt32(Console.ReadLine());


            //Choose duration of capture
            Console.WriteLine("The duration of the capture will be " + duration_TShark + " seconds. Is it acceptable Y/N");
            aux = Console.ReadLine();
            if (aux == "n" || aux == "N")
            {
                Console.WriteLine("Chose the duration of the capture in seconds : ");
                duration_TShark = Convert.ToInt32(Console.ReadLine());
            }


            //Choose Intervals
            Console.WriteLine("The statistics will be calculated with one interval. Is it acceptable? Y/N");
            aux = Console.ReadLine();
            if (aux == "n" || aux == "N")
            {
                Console.WriteLine("Enter how many seconds per interval: ");
                timeInterval_TShark = Convert.ToInt32(Console.ReadLine());
            }


            //ask url of video dash (it is better than using netstat to find the ip)
            Console.WriteLine("Study a single process? Y/N (If not then the program will make a general traffic capture searching for an MPD request but it will not work with encrypted connections)");
            aux = Console.ReadLine();
            if (aux == "n" || aux == "N")
            {
                browser = true;
            }

            if (!browser)
            {
                Console.WriteLine("A process name will be used. (As an alternative you can enter ther URL of the video to play). Accept? Y/N");
                aux = Console.ReadLine();
                if (aux == "n" || aux == "N")
                {
                    useURL = true;
                    do
                    {
                        Console.WriteLine("The following URL will be used: " + URL);
                        Console.WriteLine("Accept? Y/N");
                        aux = Console.ReadLine();
                        if (aux == "n" || aux == "N")//new URL
                        {

                            Console.WriteLine("Enter a valid URL of video");
                            URL = Console.ReadLine();
                        }
                        URL = URL.Replace("http://", ""); //remove http://
                        URL = URL.Replace("https://", ""); //remove https://
                        URL = URL.Substring(0, URL.IndexOf("/")); //remove everything after the first /
                        try
                        {
                            IPHostEntry host = Dns.GetHostEntry(URL);                   //as an alternative, it is possible to create a powershell process and execute this line: <<[System.Net.Dns]::GetHostAddresses("bitmovin-a.akamaihd.net") | select IPAddressToString>>
                            if (host.AddressList.Length > 0)
                            {
                                ipFilter = host.AddressList[0].ToString();
                                Console.WriteLine("ip found: " + ipFilter);
                                auxbool = true;
                            }
                        }
                        catch//is not a valid normal URL, check if it is valid raw IP
                        {
                            IPAddress address;
                            if (IPAddress.TryParse(URL, out address))
                            {
                                switch (address.AddressFamily)
                                {
                                    case System.Net.Sockets.AddressFamily.InterNetwork:
                                        Console.WriteLine("The URL is a valid IPv4");
                                        ipFilter = URL;
                                        auxbool = true;
                                        break;
                                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                                        Console.WriteLine("The URL is a valid IPv6. It's not tested if it will work");
                                        ipFilter = URL;
                                        auxbool = true;
                                        break;
                                    default:
                                        Console.WriteLine("The URL doesn't return a valid IP");
                                        auxbool = false;
                                        break;
                                }
                            }
                        }

                    }
                    while (!auxbool && (aux == "n" || aux == "N"));

                    Console.WriteLine("IP filter will be: " + ipFilter);
                }


                //Confirm Name of the process to capture

                do
                {
                    Console.WriteLine("Name of the process is: <<" + process_name + ">>>? Y/N");
                    input = Console.ReadLine();
                    if (input == "N" || input == "n")
                    {
                        Console.WriteLine("Write name of process to study:");
                        process_name = Console.ReadLine();
                    }
                    else
                        break;
                } while (true);



                //Wait until process is started

                while (Process.GetProcessesByName(process_name).Length == 0)
                {

                    Console.WriteLine("Waiting for user to open a process named <<" + process_name + ">>");
                    Thread.Sleep(3000);

                }


                //get PID of the process
                Process[] activeProc = Process.GetProcessesByName(process_name);
                int process_pid = activeProc[0].Id;
                Console.WriteLine("Process PID: " + process_pid);

                if (!useURL)
                {

                    //Look for PID in netstat
                    Process netstat = new Process();
                    netstat.StartInfo.FileName = "cmd";
                    netstat.StartInfo.Arguments = @"/C ""netstat -ano -p TCP | findstr """ + process_pid;
                    netstat.StartInfo.CreateNoWindow = false;
                    netstat.StartInfo.UseShellExecute = false;
                    netstat.StartInfo.RedirectStandardOutput = true;

                    do
                    {
                        Thread.Sleep(1000);
                        netstat.Start();
                        response_NetStat = netstat.StandardOutput.ReadToEnd();
                        netstat.WaitForExit();
                    } while (response_NetStat == "");
                    Thread.Sleep(1000);//after obtaining at least one IP we wait 5 more seconds because normally the first time we get a none null response from netstat, the first IP is from a google DNS service
                    netstat.Start();
                    response_NetStat = netstat.StandardOutput.ReadToEnd();
                    Console.WriteLine("----------------------");
                    Console.WriteLine(response_NetStat);
                    Console.WriteLine("++++++++++++++++++++++");
                    netstat.WaitForExit();
                    linesNetstat = Regex.Split(response_NetStat, "\r\n");
                    tokensNetstat = Regex.Split((linesNetstat[0]).TrimStart(), @"\s+|:", RegexOptions.IgnorePatternWhitespace);
                    ipFilter = tokensNetstat[3];

                    Console.WriteLine("Remote IP Found: " + ipFilter);

                }

                tshark.StartInfo.Arguments = "-i " + interface_TShark + " -f \"host "
                    + ipFilter + "\" -q -a duration:" + duration_TShark + writeToFile + captureFile
                    + " -z io,stat," + timeInterval_TShark + ",FRAMES,BYTES";
                tshark.Start();
                response_TShark = tshark.StandardOutput.ReadToEnd();
                Console.WriteLine(response_TShark);

                output.WriteLine("Capture from application <<" + process_name + ">> with PID at the moment: " + process_pid);
                output.WriteLine("Traffic captured from IP: " + ipFilter);
                output.Write(response_TShark);
                tshark.WaitForExit();
            }
            else
            {
                Console.WriteLine("Press a INTRO KEY to continue. Do it before starting the player as the program needs to analyze the first request to read the MPD file");
                Console.ReadLine();

                tshark.StartInfo.Arguments = "-i " + interface_TShark + " -q -a duration:" + duration_TShark + writeToFile + captureFile
                    + " -z io,stat," + timeInterval_TShark + ",FRAMES,BYTES";
                tshark.Start();
                response_TShark = tshark.StandardOutput.ReadToEnd();
                Console.WriteLine(response_TShark);

                output.WriteLine("General network traffic capture complete");
                output.Write(response_TShark);
                tshark.WaitForExit();
            }


            Console.WriteLine("Analysis of trace from file: " + readFile);
            //tshark.StartInfo.Arguments = " -r " + readFile + " -Y http.response -T fields -E separator=, -E quote=d -E occurrence=f -t u -e http.date -e _ws.col.Protocol -e http.time -e http.response_for.uri -e mp4.mvhd.duration -e tcp.segment.count -e tcp.reassembled.length";
            tshark.StartInfo.Arguments = " -r " + readFile + "-o tcp.calculate_timestamps:true -Y http.response -T fields -E separator=, -E quote=d -E occurrence=f -t u -e http.date -e _ws.col.Protocol -e http.time -e http.response_for.uri -e tcp.segment.count -e tcp.reassembled.length -e tcp.len";
            tshark.Start();
            response_TShark = tshark.StandardOutput.ReadToEnd();
            Console.WriteLine(response_TShark);

            output.WriteLine("Trace of frames");
            output.Write(response_TShark);
            tshark.WaitForExit();

            StreamWriter initialTraceWriter = new StreamWriter("trace.txt");
            initialTraceWriter.Write(response_TShark);
            initialTraceWriter.Flush();
            initialTraceWriter.Close();





            tshark.StartInfo.Arguments = " -r " + readFile +
                " -Y \"http.response_for.uri contains .mpd\" -o data.show_as_text:TRUE -T fields -e data.text";

            tshark.Start();
            response_TShark = tshark.StandardOutput.ReadToEnd();
            response_TShark = response_TShark.Replace(@"\n", System.Environment.NewLine);
            tshark.WaitForExit();
            Console.WriteLine("Initial MPD: ");

            if (response_TShark != "")
            {
                Console.WriteLine("There is an MPD!!! MPEG-DASH protocol has been used");
                Console.WriteLine(response_TShark);
                StreamWriter mpd = new StreamWriter("request.mpd");
                mpd.Write(response_TShark);
                mpd.Flush();
                mpd.Close();

                mpd = new StreamWriter(pathMPD);
                mpd.Write(response_TShark);
                mpd.Flush();
                mpd.Close();

                output.Write(response_TShark);
                //Analysis of mpd and results

                Console.WriteLine("\r\nStarting Analysis");

                XmlDocument doc = new XmlDocument();
                doc.PreserveWhitespace = true;
                doc.Load("request.mpd");
                XmlNamespaceManager mgr = new XmlNamespaceManager(doc.NameTable);
                mgr.AddNamespace("df", doc.DocumentElement.NamespaceURI);
                XmlNode videoTemplate = doc.SelectSingleNode(@"//df:AdaptationSet[@mimeType='video/mp4']/df:SegmentTemplate", mgr);
                XmlNodeList videoSegments = doc.SelectNodes(@"//df:AdaptationSet[@mimeType='video/mp4']/df:Representation", mgr);
                XmlNode audioTemplate = doc.SelectSingleNode(@"//df:AdaptationSet[@mimeType='audio/mp4']/df:SegmentTemplate", mgr);
                XmlNodeList audioSegments = doc.SelectNodes(@"//df:AdaptationSet[@mimeType='audio/mp4']/df:Representation", mgr);
                videoSegmentInfo[] videoInfos = new videoSegmentInfo[videoSegments.Count];
                int i = 0;
                foreach (XmlNode xn in videoSegments)
                {
                    videoInfos[i] = new videoSegmentInfo(
                        videoSegments[i].Attributes["id"].Value,
                        videoSegments[i].Attributes["width"].Value,
                        videoSegments[i].Attributes["height"].Value,
                        videoSegments[i].Attributes["bandwidth"].Value,
                        videoSegments[i].Attributes["codecs"].Value,
                        videoSegments[i].Attributes["frameRate"].Value);
                    i++;
                }
                audioSegmentInfo[] audioInfos = new audioSegmentInfo[audioSegments.Count];
                i = 0;
                foreach (XmlNode xn in audioSegments)
                {
                    audioInfos[i] = new audioSegmentInfo(
                        audioSegments[i].Attributes["id"].Value,
                        audioSegments[i].Attributes["audioSamplingRate"].Value,
                        audioSegments[i].Attributes["bandwidth"].Value,
                        audioSegments[i].Attributes["codecs"].Value);
                    i++;
                }


                StreamReader traceReader = new StreamReader("trace.txt");
                StreamWriter traceVideoWriter = new StreamWriter(pathFinalVideoTrace);
                StreamWriter traceAudioWriter = new StreamWriter(pathFinalAudioTrace);
                String line;
                traceVideoWriter.Write("http.date	_ws.col.Protocol	http.time	http.response_for.uri	tcp.segment.count	tcp.reassembled.length   tcp.len" + System.Environment.NewLine);
                traceAudioWriter.Write("http.date	_ws.col.Protocol	http.time	http.response_for.uri	tcp.segment.count	tcp.reassembled.length   tcp.len" + System.Environment.NewLine);
                int counter = 0;
                while ((line = traceReader.ReadLine()) != null)
                {
                    bool isVideoRequest = false;
                    bool isAudioRequest = false;
                    foreach (videoSegmentInfo inf in videoInfos)
                    {
                        if (line.Contains(inf.id))
                        {
                            float real_bandwidth=-1;
                            try {
                                /*
                                Console.WriteLine("**************************** Audio");
                                Console.WriteLine("Bytes: " + splits[6]);
                                Console.WriteLine("Tiempo: " + splits[3]);
                                Console.WriteLine("Bytes to float: " + float.Parse(splits[6].Replace("\"", ""), CultureInfo.InvariantCulture));
                                Console.WriteLine("Tiempo to float: " + float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture));
                                Console.WriteLine("Division: " + float.Parse(splits[6].Replace("\"", ""), CultureInfo.InvariantCulture) / float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture));
                                Console.WriteLine("****************************");
                                */
                                string[] splits=line.Split(',');
                                real_bandwidth = float.Parse(splits[6].Replace("\"",""), CultureInfo.InvariantCulture) / float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture);//There is a comma inside the date field so we select the index+1. We try to use tcp.reasembled.lenght
                            }
                            catch {
                                string[] splits = line.Split(',');
                                real_bandwidth = float.Parse(splits[7].Replace("\"", ""), CultureInfo.InvariantCulture) / float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture);//There is a comma inside the date field so we select the index+1. We try to use tcp.payload
                            }
                            Console.WriteLine(line + inf.printConsole() + ", real_bandwidth=\"" + real_bandwidth.ToString().Replace(',', '.') + "\"");
                            traceVideoWriter.Write(line + inf.printConsole() + ", real_bandwidth=\"" + real_bandwidth.ToString().Replace(',', '.') + "\"" + System.Environment.NewLine);
                            isVideoRequest = true;
                            break;
                        }
                    }

                    if (!isVideoRequest)
                        foreach (audioSegmentInfo inf in audioInfos)
                        {
                            if (line.Contains(inf.id))
                            {
                                float real_bandwidth = -1;
                                try
                                {
                                    /*
                                    Console.WriteLine("**************************** Audio");
                                    Console.WriteLine("Bytes: " + splits[6]);
                                    Console.WriteLine("Tiempo: " + splits[3]);
                                    Console.WriteLine("Bytes to float: " + float.Parse(splits[6].Replace("\"", ""), CultureInfo.InvariantCulture));
                                    Console.WriteLine("Tiempo to float: " + float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture));
                                    Console.WriteLine("Division: " + float.Parse(splits[6].Replace("\"", ""), CultureInfo.InvariantCulture) / float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture));
                                    Console.WriteLine("****************************");
                                    */

                                    string[] splits = line.Split(',');
                                    real_bandwidth = float.Parse(splits[6].Replace("\"", ""), CultureInfo.InvariantCulture) / float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture);//There is a comma inside the date field so we select the index+1
                                }
                                catch
                                {
                                    string[] splits = line.Split(',');
                                    real_bandwidth = float.Parse(splits[7].Replace("\"", ""), CultureInfo.InvariantCulture) / float.Parse(splits[3].Replace("\"", ""), CultureInfo.InvariantCulture);//There is a comma inside the date field so we select the index+1. We try to use tcp.payload
                                }
                                Console.WriteLine(line + inf.printConsole() + ", real_bandwidth=\"" + real_bandwidth.ToString().Replace(',', '.') + "\"");
                                traceAudioWriter.Write(line + inf.printConsole() + ", real_bandwidth=\"" + real_bandwidth.ToString().Replace(',', '.') + "\"" + System.Environment.NewLine);
                                isAudioRequest = true;
                                break;
                            }
                        }
                    else if (!isVideoRequest && !isAudioRequest)
                    {
                        Console.WriteLine(line);
                        traceAudioWriter.Write(line+ " \"Not Audio nor Video\"");
                        traceVideoWriter.Write(line + " \"Not Audio nor Video\"");
                    }
                    counter++;
                }

                traceVideoWriter.Flush();
                traceVideoWriter.Close();
                traceAudioWriter.Flush();
                traceAudioWriter.Close();
                traceReader.Close();


            }


            else
                Console.WriteLine("There is NOT an MPD!!! MPEG-DASH protocol hasn't been used or Encrypted Protocol has made it imposible to extract information from capture");

            output.Flush();
            output.Close();



            //Wait to exit
            Console.WriteLine("Press Escape to terminate the console application.");
            while (!(Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape))
            {
                Thread.Sleep(2000);
            }
        }
    }
}
