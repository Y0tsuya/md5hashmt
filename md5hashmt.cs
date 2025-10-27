// Revision History
// v1.0.0	First release
// v1.0.1	Add [INFO] [WARNING] to MD5 messages
//			Allocate extra character to elapsed time
// v1.0.2	Add skip option
//			Check for zero MD5
// v1.0.3	Add save messages
// v1.0.4	Add opmodes
//			Add attach mode
// v1.0.5	Change skip to match
// v1.0.6	Change time display to show days
// v1.0.7	Fix directory displayed in progress column during compute
// v1.0.8	Use event wait handle for ComputeMT instead of sleep
// v1.0.9	Change Compute mode to Verify
//			Support very long pathnames
// v1.1.0	Handle ComputedHash == null
// v1.1.1	Add MD5 Null to dump file
// v1.1.2	Change string concat to StringBuilder
// v1.1.3	Add count stats
//			Optional periodic auto-save log (minutes)
//			Change exit request from Esc -> Shift+Esc
// v1.1.4	Shorten name if in drivepool
//			Change dump file logic to avoid null conditions
// v2.0.0	Migrate to .NET 6
//			Integrate HashInterop
//			Remove AlphaFS
// v2.0.1	Migrate Thread.Abort() to cooperative exit
// v2.0.2	Break up AutoSaver sleep timer to handle cooperative exit

using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Mail;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.Reflection;
using System.Text.RegularExpressions;

public class XYConsole {

	public class XYStringParam {
		public int X;
		public int Y;
		public int Lim;
		public XYStringParam(int x, int y, int lim) {
			X = x;
			Y = y;
			Lim = lim;
		}
	}

	public struct LogStruct {
		public string Text;
		public ConsoleColor Color;
	}
	private int Offset;
	private int Lines;
	private readonly object consoleLock = new object();
	public LogStruct[] Log;
	private XYStringParam LogXY;

	public XYConsole(int ScreenLines, XYStringParam logXY, int logLines) {
		int i;

		Offset = Console.CursorTop;
		Lines = ScreenLines;
		for (i = 0; i < Lines; i++) Console.WriteLine();
		Log = new LogStruct[logLines];
		for (i = 0; i < logLines; i++) {
			Log[i] = new LogStruct();
			Log[i].Text = "";
			Log[i].Color = ConsoleColor.White;
		}
		LogXY = logXY;
		Console.CursorVisible = false;
	}

	public void PrintRaw(XYStringParam xy, string text, ConsoleColor color) {
		PrintRaw(xy.X, xy.Y, text, color);
	}

	public void PrintRaw(int x, int y, string text, ConsoleColor color) {
		Console.SetCursorPosition(x, y);
		System.Console.ForegroundColor = color;
		Console.WriteLine(text);
	}

	public void Finish() {
		Console.SetCursorPosition(0, Lines);
		System.Console.ResetColor();
		Console.CursorVisible = true;
	}

	public string FitText(string text, int charlimit) {
		string truncated;
		int i;
		int txtlen = text.Length;
		int len = 0;

		for (i = 0; i < txtlen; i++) {
			if (text[i] >= 0x0600) len += 2;
			else len++;
			if (len > charlimit) break;
		}
		truncated = text.Substring(0, i);
		return truncated;
	}

	public void WriteAt(XYStringParam xy, string text, ConsoleColor color, int lineNum) {
		WriteAt(xy.X, xy.Y + lineNum, text, xy.Lim, color);
	}

	public void WriteAt(XYStringParam xy, string text, ConsoleColor color) {
		WriteAt(xy.X, xy.Y, text, xy.Lim, color);
	}

	public void WriteAt(int x, int y, string text, int charlimit, ConsoleColor color) {
		lock (consoleLock) {
			Console.SetCursorPosition(x, y);
			Console.Write(new string(' ', charlimit));
			System.Console.ForegroundColor = color;
			Console.SetCursorPosition(x, y);
			Console.Write(FitText(text, charlimit));
		}
	}

	public void AddLog(string text, ConsoleColor color) {
		int i;
		int lines = Log.Count();

		for (i = 0; i < lines - 1; i++) {
			Log[i] = Log[i + 1];
		}
		Log[lines - 1].Text = text;
		Log[lines - 1].Color = color;
		DisplayLog();
	}

	private void DisplayLog() {
		int i;
		int lines = Log.Count();

		for (i = 0; i < lines; i++) {
			WriteAt(LogXY, Log[i].Text, Log[i].Color, i);
		}
	}
}

class ProgressPrinter {
	private int last_percent;
	XYConsole.XYStringParam GraphXY, PercentXY;
	XYConsole Con;

	public ProgressPrinter(XYConsole console, XYConsole.XYStringParam graph_xy, XYConsole.XYStringParam percent_xy) {
		last_percent = -1;
		GraphXY = graph_xy;
		PercentXY = percent_xy;
		Con = console;
	}

	public void Start() {
		Print(0);
	}

	public void Print(int percent) {
		int ticks;
		string buf;

		if (percent != last_percent) {
			last_percent = percent;
			ticks = percent * GraphXY.Lim / 100;
			buf = new string('*', ticks);
			Con.WriteAt(GraphXY, buf, ConsoleColor.Magenta);
			if (PercentXY != null) {
				Con.WriteAt(PercentXY, percent.ToString() + '%', ConsoleColor.Magenta);
			}
		}
	}

	public void Stop() {
		Print(100);
		Console.WriteLine("");
	}
}

public class FileListItem {
	public string Path;
	public long Size;
	public byte[] StoredHash;
	public byte[] ComputedHash;
}

public class ScanMTParams {
	public string Path;
	public List<FileListItem> FileList;

	public ScanMTParams(string path) {
		FileList = new List<FileListItem>();
		Path = path;
	}
};


namespace md5hashmt {


	public class md5hashmt {

		static string Version = ParseVersion(); //"v1.0.9";
		static string GuiHeader =
@"╔═════════╦═════════════════════════════╦═══════════════════╦═════════╦════════════╦════════╗
║ Project ║                             ║ 00000000/00000000 ║ Elapsed ║            ║ v1.0.0 ║
╠═════════╩════════════╦════════════════╩═══════════════════╩═════════╩════════════╩════════╣";
		static string GuiThreadLine =
@"║                      ║                                                                    ║";
		static string GuiSpacer =
@"╠══════════════════════╩════════════════════════════════════════════════════════════════════╣";
		static string GuiLogLine =
@"║                                                                                           ║";
		static string GuiFooter =
@"╚═══════════════════════════════════════════════════════════════════════════════════════════╝";
		enum ProjectMode { Seek, Path, Match, Parameter, Network, Log };
		enum Status { Success, Warning, Error };
		[Serializable]
		enum OperatingMode { Scan, Verify, Attach };

		static long MinFileSize = 0;
		static long MaxFileSize = Int64.MaxValue;
		static int MaxThreads = 1;
		static int LogLines = 10;
		static bool DoNetwork = false;
		static int NetPort = 25;
		static bool DoSsl = false;
		static bool DoLog = false;
		static string NetUser = null;
		static string NetPass = null;
		static string MailServer = null;
		static string MailFrom = null;
		static string MailTo = null;
		static string LogPath = null;
		static List<string> Roots;
		static Stopwatch TotalTime;
		//static string mailbody;
		//static string logbody;
		static StringBuilder MailBuilder = new StringBuilder();
		static StringBuilder LogBuilder = new StringBuilder();
		enum MsgType { MSG_INFO, MSG_ALERT, MSG_WARNING, MSG_ERROR };
		static MsgType MsgLevel;
		static string ProjectFile = "";
		static bool AttachLog = false;
		static int AutoSaveInterval = 0;
		static Status RuntimeStatus = Status.Success;
		static HashInterop MyMD5 = new HashInterop();
		static XYConsole.XYStringParam ProjectXY = new XYConsole.XYStringParam(12, 1, 27);
		static XYConsole.XYStringParam ProgressXY = new XYConsole.XYStringParam(42, 1, 17);
		static XYConsole.XYStringParam TotalTimeXY = new XYConsole.XYStringParam(72, 1, 10);
		static XYConsole.XYStringParam VersionXY = new XYConsole.XYStringParam(85, 1, 6);
		static XYConsole.XYStringParam MessageXY;
		static XYConsole MyXYConsole;
		static bool ExitRequested = false;
		static bool ScanCompleted = false;
		static List<string> MatchNameList;
		static bool AlreadyNotified = false;
		static OperatingMode OpMode = OperatingMode.Scan;
		static Thread TimeThread;
		static Thread AutoSaveThread;
		static string AutosaveLogFile;
		static bool AbortThreads;

		public const int LOG_ADD = 0;
		public const int LOG_SUB = 1;
		public const int LOG_UPD = 2;
		public const int LOG_INFO = 0;
		public const int LOG_ALERT = 1;
		public const int LOG_WARNING = 2;
		public const int LOG_ERROR = 3;
		static int LogCallBackHandler(int op, string msg, int errlvl, int subidx) {
			MsgType lvl = MsgType.MSG_INFO;
			switch (errlvl) {
				case LOG_INFO: lvl = MsgType.MSG_INFO; break;
				case LOG_ALERT: lvl = MsgType.MSG_ALERT; break;
				case LOG_WARNING: lvl = MsgType.MSG_WARNING; break;
				case LOG_ERROR: lvl = MsgType.MSG_ERROR; break;
				default: lvl = MsgType.MSG_INFO; break;
			}
			LogMessage(msg, lvl);
			return 0;
		}

		static void ProgressCallBackHandler(int max, int value) {
		}

		static void DoEventCallbackHandler() {
			//Write(".");
		}

		static void TextFgColor(System.ConsoleColor color) {
			System.Console.ForegroundColor = color;
		}

		static void TextBgColor(System.ConsoleColor color) {
			System.Console.BackgroundColor = color;
		}

		static void LogMessage(string msg) {
			LogMessage(msg, MsgType.MSG_INFO, true);
		}

		static void LogMessage(string msg, MsgType type) {
			LogMessage(msg, type, true);
		}

		static void LogMessage(string msg, MsgType type, bool display) {
			ConsoleColor color = ConsoleColor.Green;
			if (type >= MsgLevel) {
				switch (type) {
					case MsgType.MSG_INFO: color = ConsoleColor.Green; break;
					case MsgType.MSG_ALERT: color = ConsoleColor.Cyan; break;
					case MsgType.MSG_WARNING: color = ConsoleColor.Yellow; break;
					case MsgType.MSG_ERROR: color = ConsoleColor.Red; break;
					default: System.Console.ResetColor(); break;
				}
				if (display) MyXYConsole.AddLog(msg, color);
				MailBuilder.Append(msg + "\r\n");
				LogBuilder.Append(msg + "\r\n");
				System.Console.ResetColor();
			}
		}

		static string Shorten(string msg, int len) {
			if (msg.Length < len) return msg;
			int leftlen = len / 2 - 1;
			int rightlen = len - leftlen - 1;
			string left = msg.Substring(0, leftlen);
			string right = msg.Substring(len - rightlen - 1, rightlen);
			return left + ".." + right;
		}

		static string ParseVersion() {
			Assembly execAssembly = Assembly.GetCallingAssembly();
			AssemblyName name = execAssembly.GetName();
			string ver = String.Format("{0}.{1}.{2}", name.Version.Major.ToString(), name.Version.Minor.ToString(), name.Version.Build.ToString());
			return ver;
		}

		static string MakeLongPath(string path) {
			string longpath;
			bool isUNC;

			if (path.Substring(0, 2) == "\\\\") isUNC = true;
			else isUNC = false;
			if (isUNC) {
				path = path.Replace("\\\\", "\\");
				longpath = "\\\\?\\UNC" + path;
			} else {
				longpath = "\\\\?\\" + path;
			}
			return longpath;
		}

		static string FixRootDir(string path) {
			string root;
			bool isUNC;
			char[] trimchars = { '\\' };

			if (path.Substring(0, 2) == "\\\\") isUNC = true;
			else isUNC = false;
			root = path.Trim(trimchars);
			//			root = path.Replace("\\\\", "\\");
			if (isUNC) root = "\\\\" + root;
			return root;
		}

		static string StripRoot(string root, string path) {
			string rpath = path;
			char[] trimchars = { '\\' };

			rpath = rpath.Substring(root.Length);
			rpath = rpath.Trim(trimchars);
			return rpath;
		}

		const long KB = 1024;
		const long MB = KB * 1024;
		const long GB = MB * 1024;
		const long TB = GB * 1024;

		static long DecodeByteSize(string num) {
			long bytes;

			if (num.Substring(num.Length - 2) == "TB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * TB;
			} else if (num.Substring(num.Length - 2) == "GB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * GB;
			} else if (num.Substring(num.Length - 2) == "MB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * MB;
			} else if (num.Substring(num.Length - 2) == "KB") {
				bytes = Convert.ToInt64(num.Substring(0, num.Length - 2)) * KB;
			} else {
				bytes = Convert.ToInt64(num);
			}
			return bytes;
		}

		static string EncodeByteSize(long num) {
			string si;
			double fp = 0;
			string unit = "B";
			int dec = 0;
			string fmt = "";

			if (num > TB) {
				fp = (double)num / (double)TB;
				unit = "TB";
			} else if (num > GB) {
				fp = (double)num / (double)GB;
				unit = "GB";
			} else if (num > MB) {
				fp = (double)num / (double)MB;
				unit = "MB";
			} else if (num > KB) {
				fp = (double)num / (double)KB;
				unit = "KB";
			} else {
				fp = num;
				unit = " Byte";
			}
			if (fp >= 100) dec = 0;
			else if (fp >= 10) dec = 1;
			else dec = 2;
			fmt = "{0:F" + dec.ToString() + "}" + unit;
			si = String.Format(fmt, fp);

			return si;
		}

		static string GetFolderName(string path) {
			char[] delims = new char[] { '\\' };
			string[] tokens;
			tokens = path.Split(delims, StringSplitOptions.RemoveEmptyEntries);
			return tokens[tokens.Count() - 1];
		}

		static void LoadProject(string prjpath) {
			ProjectMode mode = ProjectMode.Seek;
			Roots = new List<string>();
			string buf;
			char[] delims = new char[] { '=' };
			string[] tokens;
			MatchNameList = new List<string>();

			if (!File.Exists(prjpath)) {
				LogMessage("[ERROR] Project file " + prjpath + " not found.", MsgType.MSG_ERROR);
				LogMessage("Exiting...", MsgType.MSG_ERROR);
				CleanExit();
			}
			StreamReader tr = new StreamReader(prjpath);
			while (!tr.EndOfStream) {
				buf = tr.ReadLine();
				buf = buf.Trim();
				if (buf == "") continue;
				if (buf[0] == '#') {
					continue;
				} else if (buf == "[Path]") {
					mode = ProjectMode.Path;
				} else if (buf == "[Match]") {
					mode = ProjectMode.Match;
				} else if (buf == "[Parameter]") {
					mode = ProjectMode.Parameter;
				} else if (buf == "[Network]") {
					mode = ProjectMode.Network;
					DoNetwork = true;
				} else if (buf == "[Log]") {
					mode = ProjectMode.Log;
					DoLog = true;
				} else if (mode == ProjectMode.Path) {
					tokens = buf.Split(delims, StringSplitOptions.RemoveEmptyEntries);
					if (tokens.Count() > 0) {
						tokens[1] = tokens[1].Trim();
						switch (tokens[0].ToLower().Trim()) {
							case "root":
								Roots.Add(FixRootDir(tokens[1]));
								break;
							default: break;
						}
					}
				} else if (mode == ProjectMode.Match) {
					tokens = buf.Split(delims, StringSplitOptions.RemoveEmptyEntries);
					if (tokens.Count() > 0) {
						tokens[1] = tokens[1].Trim();
						switch (tokens[0].ToLower().Trim()) {
							case "name":
								MatchNameList.Add(tokens[1].ToLower());
								break;
							default: break;
						}
					}
				} else if (mode == ProjectMode.Parameter) {
					tokens = buf.Split(delims, StringSplitOptions.RemoveEmptyEntries);
					if (tokens.Count() > 0) {
						tokens[1] = tokens[1].Trim();
						switch (tokens[0].ToLower().Trim()) {
							case "minfilesize":
								MinFileSize = DecodeByteSize(tokens[1]);
								break;
							case "maxfilesize":
								MaxFileSize = DecodeByteSize(tokens[1]);
								break;
							case "maxthreads":
								MaxThreads = Int32.Parse(tokens[1]);
								break;
							case "loglines":
								LogLines = Int32.Parse(tokens[1]);
								break;
							default: break;
						}
					}
				} else if (mode == ProjectMode.Network) {
					tokens = buf.Split(delims, StringSplitOptions.RemoveEmptyEntries);
					if (tokens.Count() > 0) {
						tokens[1] = tokens[1].Trim();
						switch (tokens[0].ToLower().Trim()) {
							case "to":
								MailTo = tokens[1];
								break;
							case "from":
								MailFrom = tokens[1];
								break;
							case "server":
								MailServer = tokens[1];
								break;
							case "port":
								NetPort = Convert.ToInt32(tokens[1]);
								break;
							case "user":
								NetUser = tokens[1];
								break;
							case "pass":
								NetPass = tokens[1];
								break;
							case "ssl":
								if ((tokens[1] == "true") || (tokens[1] == "yes")) {
									DoSsl = true;
								} else {
									DoSsl = false;
								}
								break;
							default: break;
						}
					}
				} else if (mode == ProjectMode.Log) {
					tokens = buf.Split(delims, StringSplitOptions.RemoveEmptyEntries);
					if (tokens.Count() > 0) {
						tokens[1] = tokens[1].Trim();
						switch (tokens[0].ToLower().Trim()) {
							case "path":
								LogPath = tokens[1];
								break;
							case "attach":
								if (tokens[1].ToLower() == "yes") {
									AttachLog = true;
								}
								break;
							case "autosave":
								AutoSaveInterval = Convert.ToInt32(tokens[1]);
								break;
							default: break;
						}
					}
				}
			}
			tr.Close();
		}

		static void CheckProject() {
			int i;
			if (Roots.Count == 0) {
				LogMessage("[ERROR] No Source root specified", MsgType.MSG_ERROR);
				LogMessage("Exiting...", MsgType.MSG_ERROR);
				CleanExit();
			}
			for (i = 0; i < Roots.Count; i++) {
				if (!Directory.Exists(Roots[i])) {
					LogMessage("[ERROR] Root dir not found: " + Roots[i], MsgType.MSG_ERROR);
					LogMessage("Exiting...", MsgType.MSG_ERROR);
					CleanExit();
				} else {
					LogMessage("[PATH] Root #" + i.ToString() + ": " + Roots[i], MsgType.MSG_ALERT);

				}
			}
			for (i = 0; i < MatchNameList.Count; i++) {
				LogMessage("[MATCH] Name=" + MatchNameList[i]);
			}
			LogMessage("[MODE] " + OpMode.ToString(), MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] MinFileSize=" + MinFileSize, MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] MaxFileSize=" + MaxFileSize, MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] MaxThreads=" + MaxThreads, MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] LogLines=" + LogLines, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] mailto: " + MailTo, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] mailfrom: " + MailFrom, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] mailserver: " + MailServer, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] port: " + NetPort, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] userid: " + NetUser, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] passwd: " + NetPass, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] SSL: " + (DoSsl ? "Yes" : "No"), MsgType.MSG_ALERT);
			LogMessage("[LOG] path: " + LogPath, MsgType.MSG_ALERT);
			LogMessage("[LOG] attach: " + AttachLog, MsgType.MSG_ALERT);
		}

		static void SendMail(string host, int port, bool ssl, string user, string pass, string from, string to, string subject, string body) {
			SmtpClient client = new SmtpClient(host, port);
			MailAddress addrFrom = new MailAddress(from, "md5hashmt", System.Text.Encoding.UTF8);
			MailAddress addrTo = new MailAddress(to, to, System.Text.Encoding.UTF8);
			MailMessage message = new MailMessage(addrFrom, addrTo);
			client.EnableSsl = ssl;
			if ((user != "") && (pass != "")) {
				client.Credentials = new NetworkCredential(user, pass);
			}
			client.ServicePoint.MaxIdleTime = 2;
			message.Subject = subject;
			message.SubjectEncoding = System.Text.Encoding.UTF8;
			message.Body = body;
			message.BodyEncoding = System.Text.Encoding.UTF8;
			try {
				client.Send(message);
			} catch (ArgumentNullException ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
			} catch (ObjectDisposedException ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
			} catch (SmtpFailedRecipientsException ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
			} catch (SmtpException ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				//				LogMessage(ex.InnerException.Message, MsgType.MSG_ERROR);
			} catch (Exception ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
			}
			client.Dispose();
			message.Dispose();
		}

		static void SaveLog(string filename, string body) {
			try {
				StreamWriter tw = new StreamWriter(filename);
				tw.Write(body);
				tw.Flush();
				tw.Close();
				tw.Dispose();
			} catch (Exception ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
			}
		}

		static void SaveDump(string filename, List<ScanMTParams> rootParams) {
			int i, j;
			byte[] zeroes = new byte[16];

			try {
				StreamWriter tw = new StreamWriter(filename);
				for (i = 0; i < RootList.Count; i++) {
					//LogMessage("[DUMP] Rootlist#" + i + ", " + RootList[i].FileList.Count + " files");
					for (j = 0; j < RootList[i].FileList.Count; j++) {
						//LogMessage("[DUMP] " + RootList[i].FileList[j].Path);
						if (RootList[i].FileList[j].StoredHash == null) {
							tw.WriteLine(ShortenPath(RootList[i].FileList[j].Path) + "\tNo MD5" + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
						} else if (RootList[i].FileList[j].StoredHash.SequenceEqual(zeroes)) {
							tw.WriteLine(ShortenPath(RootList[i].FileList[j].Path) + "\tMD5 Zeroes" + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
						} else if ((OpMode == OperatingMode.Verify) && (RootList[i].FileList[j].ComputedHash == null)) {
							tw.WriteLine(ShortenPath(RootList[i].FileList[j].Path) + "\tMD5 Null" + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].StoredHash));
						} else if (RootList[i].FileList[j].ComputedHash == null) {
							// do nothing
						} else {
							if (RootList[i].FileList[j].StoredHash.SequenceEqual(RootList[i].FileList[j].ComputedHash)) {
								tw.WriteLine(ShortenPath(RootList[i].FileList[j].Path) + "\tMD5 Match" + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
							} else {
								tw.WriteLine(ShortenPath(RootList[i].FileList[j].Path) + "\tMD5 Mismatch" + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + MyMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
							}
						}
					}
				}
				tw.Flush();
				tw.Close();
				tw.Dispose();
			} catch (Exception ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
			}
		}

		static void CleanExit() {
			RuntimeStatus = Status.Error;
			if (TotalTime != null) TotalTime.Stop();
			Notify(RuntimeStatus);
			System.Console.ResetColor();
			//			Console.OutputEncoding = System.Text.Encoding.Default;
			if (ScanCompleted) {
				//				SaveScan(scanFile);
			}
			Environment.Exit(1);
		}

		static bool MatchList(string path, List<string> List) {
			bool match;

			match = false;
			foreach (string expr in List) {
				if (expr.Length > 0) {
					if (path.Contains(expr)) {
						match = true;
						break;
					}
				}
			}
			//if (match) LogMessage("[MATCH] " + Path.GetFileName(path));
			//else LogMessage("[NOMATCH] " + Path.GetFileName(path));
			return match;
		}

		static void Notify(Status statusCode) {
			string logfile, dumpfile;
			string datepat = @"yyyy-MM-dd HH-mm-ss tt";
			string status;
			string content;

			if (AlreadyNotified) return;
			AlreadyNotified = true;
			switch (statusCode) {
				case Status.Success: status = " [Success]"; break;
				case Status.Warning: status = " [Warning]"; break;
				case Status.Error: status = " [Error]"; break;
				default: status = " [Success]"; break;
			}
			LogMessage("[INFO] Logfile size: " + LogBuilder.Length + " bytes");
			if (DoNetwork) {
				LogMessage("[INFO] Sending notification email");
				if (AttachLog) {
					content = MailBuilder.ToString();
				} else {
					content = "See Log File for details";
				}
				SendMail(MailServer, NetPort, DoSsl, NetUser, NetPass, MailFrom, MailTo, "md5hashmt " + ProjectFile + status, content);
			}
			if (DoLog) {
				logfile = LogPath + "\\" + Path.GetFileNameWithoutExtension(ProjectFile) + " " + DateTime.Now.ToString(datepat) + status + ".log";
				LogMessage("[INFO] Saving log file " + logfile);
				SaveLog(logfile, LogBuilder.ToString());
				LogMessage("[INFO] log file saved");
			}
			dumpfile = LogPath + "\\" + Path.GetFileNameWithoutExtension(ProjectFile) + " " + DateTime.Now.ToString(datepat) + status + ".dump";
			LogMessage("[INFO] Saving dump file " + dumpfile);
			SaveDump(dumpfile, RootList);
			LogMessage("[INFO] dump file saved");
			System.Console.ResetColor();
		}

		static void OnProcessExit(object sender, EventArgs e) {

		}

		static void PrintHelp() {
			MyXYConsole.AddLog("md5hashmt " + Version + " - (C)2020 Bo-Yi Lin", ConsoleColor.Red);
			MyXYConsole.AddLog("syntax: md5hashmt -p [prjpath] -m [mode] -l verbosity", ConsoleColor.Red);
			MyXYConsole.AddLog("verbosity: INFO, WARNING, ERROR", ConsoleColor.Red);
			MyXYConsole.AddLog("mode: SCAN, VERIFY, ATTACH", ConsoleColor.Red);
		}

		static void PrintTime() {
			int processed, total;
			ConsoleKeyInfo cki;
			while ((TotalTime != null) && !AbortThreads) {
				lock (countLock) {
					processed = ProcessedFiles;
					total = TotalFiles;
				}
				MyXYConsole.WriteAt(TotalTimeXY, TotalTime.Elapsed.ToString("G"), ConsoleColor.Cyan);
				MyXYConsole.WriteAt(ProgressXY, String.Format("{0,8}/{1,-8}", processed, total), ConsoleColor.Cyan);
				if (Console.KeyAvailable) {
					cki = Console.ReadKey();
					if ((cki.Key == ConsoleKey.Escape) && cki.Modifiers.HasFlag(ConsoleModifiers.Shift)) {
						LogMessage("[WARNING] Exit requested", MsgType.MSG_WARNING);
						RuntimeStatus = Status.Warning;
						ExitRequested = true;
					}
				}
				Thread.Sleep(250);
			}
		}

		static void AutoSaver() {
			while ((AutoSaveInterval > 0) && !AbortThreads) {
				LogMessage("[INFO] AutoSaving log file " + AutosaveLogFile);
				SaveLog(AutosaveLogFile, LogBuilder.ToString());
				for (int i = 0; i < AutoSaveInterval; i++) {
					for (int j = 0; j < 60; j++) {
						Thread.Sleep(1000);
						if (AbortThreads) break;
					}
					if (AbortThreads) break;
				}
			}
		}

		static void SaveScan(string filename) {
			BinaryFormatter bf = new BinaryFormatter();
			FileStream fs;

			LogMessage("[INFO] Save scan data to " + filename);
			try {
				fs = new FileStream(filename, FileMode.Create);
			} catch (Exception ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				//				CleanExit();
				return;
			}
			/*			bf.Serialize(fs, SourcePaths);
						bf.Serialize(fs, TargetPaths);
						bf.Serialize(fs, SourceTable);
						bf.Serialize(fs, TargetTable);*/
			fs.Close();
		}

		static void LoadScan(string filename) {
			BinaryFormatter bf = new BinaryFormatter();
			FileStream fs;

			LogMessage("[INFO] Load Scan data from " + filename);
			try {
				fs = new FileStream(filename, FileMode.Open);
			} catch (Exception ex) {
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
				return;
			}
			/*			SourcePaths = (List<string>)bf.Deserialize(fs);
						TargetPaths = (List<string>)bf.Deserialize(fs);
						SourceTable = (List<FileTableItem>)bf.Deserialize(fs);
						TargetTable = (List<FileTableItem>)bf.Deserialize(fs);*/
			fs.Close();
		}

		static int ScanIndex, ComputeIndex;
		static readonly object paramLock = new object();
		static List<ScanMTParams> RootList;
		static int TotalFiles = 0;
		static int ProcessedFiles = 0;
		static readonly object countLock = new object();

		static void LaunchScanMT() {
			int i;
			bool IsAlive;
			DateTime start, end;
			Thread[] scanThreads;
			XYConsole.XYStringParam[] pathXY = new XYConsole.XYStringParam[MaxThreads];
			XYConsole.XYStringParam[] progXY = new XYConsole.XYStringParam[MaxThreads];

			start = DateTime.Now;
			scanThreads = new Thread[MaxThreads];
			ScanIndex = 0;
			LogMessage("[INFO] Launch Scans");
			for (i = 0; i < MaxThreads; i++) {
				pathXY[i] = new XYConsole.XYStringParam(2, 3 + i, 20);
				progXY[i] = new XYConsole.XYStringParam(25, 3 + i, 66);
				scanThreads[i] = new Thread(() => ScanMT(pathXY[i], progXY[i]));
				scanThreads[i].Name = i.ToString();
				scanThreads[i].Start();
				Thread.Sleep(100);
			}
			IsAlive = true;
			while (IsAlive) {
				IsAlive = false;
				for (i = 0; i < MaxThreads; i++) {
					IsAlive = IsAlive | scanThreads[i].IsAlive;
				}
				Thread.Sleep(100);
			}
			LogMessage("[INFO] Finished Scans");
			end = DateTime.Now;
			TimeSpan timediff = end.Subtract(start);
			LogMessage("Elapsed Time = " + timediff.ToString());
		}

		static string RightJustify(string instr, int len) {
			string sub;
			if (instr.Length > len) {
				sub = instr.Substring(instr.Length - len);
			} else {
				sub = instr;
			}
			return sub;
		}

		static void ScanMT(XYConsole.XYStringParam pathXY, XYConsole.XYStringParam progXY) {
			ScanMTParams Params;
			int myIndex;

			while (true) {
				if (ExitRequested) return;
				lock (paramLock) {
					myIndex = ScanIndex;
					if (myIndex >= RootList.Count()) return; // no more to do
					ScanIndex++;
				}
				Params = RootList[myIndex];
				MyXYConsole.WriteAt(pathXY, RightJustify(ShortenPath(Params.Path), 20), ConsoleColor.Green);
				Scan(Params.Path, Params.Path, pathXY, progXY, Params.FileList);
				MyXYConsole.WriteAt(pathXY, "Idle", ConsoleColor.Green);
				MyXYConsole.WriteAt(progXY, " ", ConsoleColor.Green);
			}
		}

		static void Scan(string root, string path,
			XYConsole.XYStringParam pathXY, XYConsole.XYStringParam progXY,
			List<FileListItem> fileList) {
			List<string> dirPaths, filePaths;
			string dirName, fileName;
			string child;
			FileInfo fi = null;
			byte[] zeroes = new byte[16];

			if (ExitRequested) return;
			dirPaths = null;
			filePaths = null;
			MyXYConsole.WriteAt(progXY, RightJustify(ShortenPath(path), 66), ConsoleColor.Green);
			try {
				dirPaths = new List<string>(Directory.EnumerateDirectories(path));
			} catch (Exception ex) {
				LogMessage("[ERROR] Cannot list directories in " + ShortenPath(path), MsgType.MSG_ERROR);
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
			}
			try {
				filePaths = new List<string>(Directory.EnumerateFiles(path));
			} catch (Exception ex) {
				LogMessage("[ERROR] Cannot list files in " + ShortenPath(path), MsgType.MSG_ERROR);
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
			}
			lock (countLock) {
				TotalFiles += filePaths.Count;
			}
			foreach (string dirPath in dirPaths) {
				dirName = GetFolderName(dirPath);
				//				LogMessage("[DEBUG] " + dirName);
				if ((dirName == "$RECYCLE.BIN") | (dirName == "System Volume Information")) {
					LogMessage("[SKIP] " + ShortenPath(dirName));
				} else if ((File.GetAttributes(path + "\\" + dirName) & System.IO.FileAttributes.ReparsePoint) == System.IO.FileAttributes.ReparsePoint) {
					LogMessage("[LINK] " + ShortenPath(dirName));
				} else {
					child = path + "\\" + dirName;
					Scan(root, child, pathXY, progXY, fileList);
				}
			}
			foreach (string filePath in filePaths) {
				if (!MatchList(filePath.ToLower(), MatchNameList)) continue;
				if (ExitRequested) break;
				System.IO.FileAttributes fileAttributes = System.IO.FileAttributes.Normal;
				fileName = Path.GetFileName(filePath);
				// debug
				//LogMessage("[DEBUG] scan " + filePath, MsgType.MSG_INFO);
				// debug
				try {
					fileAttributes = File.GetAttributes(filePath);
				} catch (Exception ex) {
					LogMessage("[WARNING] " + ex.Message, MsgType.MSG_WARNING);
					continue;
				}
				if ((fileAttributes & System.IO.FileAttributes.ReparsePoint) == System.IO.FileAttributes.ReparsePoint) {
					LogMessage("[LINK] " + ShortenPath(filePath));
				} else {
					FileListItem item = new FileListItem();
					try {
						fi = new FileInfo(filePath);
					} catch (Exception ex) {
						string buf = ex.Message;
						LogMessage("[WARNING] " + ex.Message, MsgType.MSG_WARNING);
						CleanExit();
					}
					if ((fi.Length >= MinFileSize) && (fi.Length < MaxFileSize)) {
						item.Path = filePath;
						item.StoredHash = MyMD5.Read(filePath);
						if (item.StoredHash == null) {
							LogMessage("[WARNING] " + ShortenPath(item.Path) + " No MD5");
						} else if (item.StoredHash.SequenceEqual(zeroes)) {
							LogMessage("[WARNING] " + ShortenPath(item.Path) + " MD5 Zeroes");
						}
						item.Size = fi.Length;
						fileList.Add(item);
					}
				}
			}
		}

		static string ShortenPath(string filePath) {
			Regex rgx = new Regex(@"^.*PoolPart.(.*?)\\");
			return rgx.Replace(filePath, "");
		}

		static EventWaitHandle WaitComputeLaunch;

		static void LaunchComputeMT() {
			int i;
			bool IsAlive;
			DateTime start, end;
			Thread[] computeThreads;
			XYConsole.XYStringParam[] pathXY = new XYConsole.XYStringParam[MaxThreads];
			XYConsole.XYStringParam[] progXY = new XYConsole.XYStringParam[MaxThreads];
			WaitComputeLaunch = new AutoResetEvent(false);

			start = DateTime.Now;
			computeThreads = new Thread[MaxThreads];
			ComputeIndex = 0;
			LogMessage("[INFO] Launch Compute");
			for (i = 0; i < MaxThreads; i++) {
				pathXY[i] = new XYConsole.XYStringParam(2, 3 + i, 20);
				progXY[i] = new XYConsole.XYStringParam(25, 3 + i, 66);
				computeThreads[i] = new Thread(() => ComputeMT(pathXY[i], progXY[i]));
				computeThreads[i].Name = i.ToString();
				computeThreads[i].Start();
				WaitComputeLaunch.WaitOne();
				//Thread.Sleep(100);
			}
			IsAlive = true;
			while (IsAlive) {
				IsAlive = false;
				for (i = 0; i < MaxThreads; i++) {
					IsAlive = IsAlive | computeThreads[i].IsAlive;
				}
				Thread.Sleep(100);
			}
			LogMessage("[INFO] Finished Compute");
			end = DateTime.Now;
			TimeSpan timediff = end.Subtract(start);
			LogMessage("Elapsed Time = " + timediff.ToString());
		}

		static void ComputeMT(XYConsole.XYStringParam pathXY, XYConsole.XYStringParam progXY) {
			ScanMTParams Params;
			int myIndex;

			WaitComputeLaunch.Set();
			while (true) {
				if (ExitRequested) return;
				lock (paramLock) {
					myIndex = ComputeIndex;
					if (myIndex >= RootList.Count()) return; // no more to do
					ComputeIndex++;
				}
				Params = RootList[myIndex];
				MyXYConsole.WriteAt(pathXY, RightJustify(ShortenPath(Params.Path), 20), ConsoleColor.Green);
				Compute(Params.Path, Params.Path, pathXY, progXY, Params.FileList);
				MyXYConsole.WriteAt(pathXY, "Idle", ConsoleColor.Green);
				MyXYConsole.WriteAt(progXY, " ", ConsoleColor.Green);
			}
		}

		static void Compute(string root, string path,
			XYConsole.XYStringParam pathXY, XYConsole.XYStringParam progXY,
			List<FileListItem> fileList) {
			int i, p;
			byte[] zeroes = new byte[16];

			ProgressPrinter progress = new ProgressPrinter(MyXYConsole, progXY, null);
			progress.Start();
			for (i = 0; i < fileList.Count; i++) {
				if (ExitRequested) return;
				//if (Path.GetExtension(fileList[i].Path) == ".JPG") {
				//	LogMessage("[DEBUG] scan " + Path.GetFileName(fileList[i].Path), MsgType.MSG_INFO);
				//}
				if (fileList[i].StoredHash == null) {
					if (OpMode == OperatingMode.Attach) {
						fileList[i].ComputedHash = MyMD5.Generate(fileList[i].Path);
						if (MyMD5.Attach(fileList[i].Path, fileList[i].ComputedHash)) {
							LogMessage("[INFO] " + ShortenPath(fileList[i].Path) + " MD5 Attach");
						} else {
							LogMessage("[WARNING] " + ShortenPath(fileList[i].Path) + " MD5 Attach Failed");
							//LogMessage("[EXCEPTION] " + MyMD5.ExceptionError);
						}
					} else {
						LogMessage("[INFO] " + ShortenPath(fileList[i].Path) + " No MD5");
					}
				} else if (fileList[i].StoredHash.SequenceEqual(zeroes)) {
					if (OpMode == OperatingMode.Attach) {
						fileList[i].ComputedHash = MyMD5.Generate(fileList[i].Path);
						MyMD5.Detach(fileList[i].Path, true);
						if (MyMD5.Attach(fileList[i].Path, fileList[i].ComputedHash)) {
							LogMessage("[INFO] " + ShortenPath(fileList[i].Path) + " MD5 Recompute");
						} else {
							LogMessage("[WARNING] " + ShortenPath(fileList[i].Path) + " MD5 Attach Failed");
							//LogMessage("[EXCEPTION] " + MyMD5.ExceptionError);
						}
					} else {
						LogMessage("[WARNING] " + ShortenPath(fileList[i].Path) + " MD5 Zeros");
					}
				} else if (OpMode == OperatingMode.Verify) {
					fileList[i].ComputedHash = MyMD5.Generate(fileList[i].Path);
					if (fileList[i].ComputedHash == null) {
						LogMessage("[WARNING] " + ShortenPath(fileList[i].Path) + " MD5 Null", MsgType.MSG_WARNING);
					} else if (!fileList[i].StoredHash.SequenceEqual(fileList[i].ComputedHash)) {
						LogMessage("[WARNING] " + ShortenPath(fileList[i].Path) + " MD5 Mismatch", MsgType.MSG_WARNING);
					}
				}
				p = (i * 100) / fileList.Count;
				progress.Print(p);
				lock (countLock) {
					ProcessedFiles++;
				}
			}
			progress.Stop();
		}

		static void Main(string[] args) {
			int i;
			int c;

			AbortThreads = false;
			MyMD5.LogCallBack = LogCallBackHandler;
			MessageXY = new XYConsole.XYStringParam(2, 10, 89);
			MyXYConsole = new XYConsole(20, MessageXY, LogLines);
			if (args.Length == 0) {
				LogMessage("[ERROR] No arguments specified", MsgType.MSG_ERROR, true);
				PrintHelp();
				CleanExit();
			}
			MsgLevel = MsgType.MSG_INFO;
			AppDomain.CurrentDomain.ProcessExit += new EventHandler(OnProcessExit);
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			for (c = 0; c < args.Length; c++) {
				if (args[c] == "-p") {
					ProjectFile = args[c + 1];
					c++;
				} else if (args[c] == "-l") {
					switch (args[c + 1].ToLower()) {
						case "info": MsgLevel = MsgType.MSG_INFO; break;
						case "alert": MsgLevel = MsgType.MSG_ALERT; break;
						case "warning": MsgLevel = MsgType.MSG_WARNING; break;
						case "error": MsgLevel = MsgType.MSG_ERROR; break;
						default: break;
					}
					c++;
				} else if (args[c] == "-m") {
					switch (args[c + 1].ToLower()) {
						case "scan": OpMode = OperatingMode.Scan; break;
						case "verify": OpMode = OperatingMode.Verify; break;
						case "attach": OpMode = OperatingMode.Attach; break;
						default: break;
					}
				}
			}

			if (ProjectFile == "") {
				MyXYConsole.Finish(); TotalTime = null;
				LogMessage("[ERROR] No project file specified", MsgType.MSG_ERROR, true);
				PrintHelp();
				CleanExit();
			}
			Roots = new List<string>();
			LoadProject(ProjectFile);
			MessageXY = new XYConsole.XYStringParam(2, 4 + MaxThreads, 89);
			MyXYConsole = new XYConsole(5 + MaxThreads + LogLines, MessageXY, LogLines);
			Console.Clear();
			MyXYConsole.PrintRaw(0, 0, GuiHeader, ConsoleColor.Yellow);
			for (i = 0; i < MaxThreads; i++) {
				MyXYConsole.PrintRaw(0, 3 + i, GuiThreadLine, ConsoleColor.Yellow);
			}
			MyXYConsole.PrintRaw(0, 3 + MaxThreads, GuiSpacer, ConsoleColor.Yellow);
			for (i = 0; i < LogLines; i++) {
				MyXYConsole.PrintRaw(0, 4 + MaxThreads + i, GuiLogLine, ConsoleColor.Yellow);
			}
			MyXYConsole.PrintRaw(0, 4 + MaxThreads + LogLines, GuiFooter, ConsoleColor.Yellow);
			MyXYConsole.WriteAt(VersionXY, "v" + Version, ConsoleColor.Cyan);
			CheckProject();
			RootList = new List<ScanMTParams>();
			for (i = 0; i < Roots.Count; i++) {
				ScanMTParams Params = new ScanMTParams(Roots[i]);
				RootList.Add(Params);
			}
			TotalTime = new Stopwatch();
			TotalTime.Start();
			TimeThread = new Thread(PrintTime);
			TimeThread.Start();
			if (DoLog && (AutoSaveInterval > 0)) {
				AutosaveLogFile = LogPath + "\\" + Path.GetFileNameWithoutExtension(ProjectFile) + " " + DateTime.Now.ToString(@"yyyy-MM-dd HH-mm-ss tt") + "_autosave.log";
				AutoSaveThread = new Thread(AutoSaver);
				AutoSaveThread.Start();
			}
			MyXYConsole.WriteAt(ProjectXY, ProjectFile, ConsoleColor.Cyan);
			LaunchScanMT();
			LaunchComputeMT();
			AbortThreads = true;
			//TimeThread.Abort();
			while (TimeThread.IsAlive) Thread.Sleep(250);
			if (AutoSaveThread != null) {
				//AutoSaveThread.Abort();
				while (AutoSaveThread.IsAlive) Thread.Sleep(250);
				File.Delete(AutosaveLogFile);
			}
			Notify(RuntimeStatus);
			TotalTime.Stop();
			TotalTime = null;
			MyXYConsole.Finish();
			System.Console.ResetColor();
		}
	}
}
