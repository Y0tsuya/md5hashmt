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

using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Mail;
using System.Diagnostics;
//using Delimon.Win32.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.Reflection;

public class MD5Alpha {
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	static extern uint CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityFileAttributes, uint dwCreationDisposition, uint dwFlagAndAttributes, IntPtr hTemplateFile);
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	static extern bool DeleteFileW(string lpFileName);
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	static extern bool CloseHandle(uint handle);
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	static extern bool ReadFile(uint hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	static extern int WriteFile(uint hFile, [In] byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

	public const uint GENERIC_ALL = 0x10000000;
	public const uint GENERIC_EXECUTE = 0x20000000;
	public const uint GENERIC_WRITE = 0x40000000;
	public const uint GENERIC_READ = 0x80000000;
	public const uint FILE_SHARE_READ = 0x00000001;
	public const uint FILE_SHARE_WRITE = 0x00000002;
	public const uint FILE_SHARE_DELETE = 0x00000004;
	public const uint CREATE_NEW = 1;
	public const uint CREATE_ALWAYS = 2;
	public const uint OPEN_EXISTING = 3;
	public const uint OPEN_ALWAYS = 4;
	public const uint TRUNCATE_EXISTING = 5;
	public const int FILE_ATTRIBUTE_NORMAL = 0x80;

	public long minsize = 0, maxsize = long.MaxValue;
	public string hashString;

	public MD5Alpha() {
	}

	public string GetHashString(byte[] hash) {
		if (hash == null) return "";
		return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
	}

	public byte[] Generate(string filename) {
		byte[] hash;
		string fullpath = Alphaleonis.Win32.Filesystem.Path.GetFullPath(filename);

		try {
			using (var md5 = MD5.Create()) {
				using (var stream = Alphaleonis.Win32.Filesystem.File.OpenRead(filename)) {
					hash = md5.ComputeHash(stream);
					return hash;
				}
			}
		} catch (IOException ex) {
			string buf = ex.Message;
			return null;
		}
	}

	public byte[] Read(string filename) {
		byte[] hash = new byte[16];
		uint bytesread = 0;
		uint handle = 0;

		try {
			handle = CreateFileW(@"\\?\" + filename + ":md5", GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
		} catch (Exception ex) {
			string buf = ex.Message;
			return null;
		}
		if (handle == 0xFFFFFFFF) { // no MD5
			return null;
		}
		ReadFile(handle, hash, 16, out bytesread, IntPtr.Zero);
		CloseHandle(handle);
		return hash;
	}

	public bool Verify(string filename) {
		byte[] storedhash = new byte[16];
		byte[] genhash;
		uint bytesread = 0;
		uint handle = 0;

		try {
			handle = CreateFileW(filename + ":md5", GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
		} catch (Exception ex) {
			string buf = ex.Message;
			return false;
		}
		if (handle == 0xffffffff) {
			return false;
		}
		ReadFile(handle, storedhash, 16, out bytesread, IntPtr.Zero);
		CloseHandle(handle);
		genhash = Generate(filename);
		if (genhash.SequenceEqual(storedhash)) return true;
		else return false;
	}

	public bool Attach(string filename) {
		uint handle = 0;
		byte[] genhash;

		try {
			handle = CreateFileW(filename + ":md5", GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
		} catch (Exception ex) {
			string buf = ex.Message;
			return false;
		}
		if (handle != 0xFFFFFFFF) {
			return false;
		}
		genhash = Generate(filename);
		return Attach(filename, genhash);
	}

	public bool Attach(string filename, byte[] hash) {
		uint byteswritten = 0;
		uint handle = 0;
		DateTime modify;

		modify = Alphaleonis.Win32.Filesystem.File.GetLastWriteTime(filename);

		try {
			handle = CreateFileW(filename + ":md5", GENERIC_WRITE, FILE_SHARE_WRITE, IntPtr.Zero, OPEN_ALWAYS, 0, IntPtr.Zero);
		} catch (Exception ex) {
			string buf = ex.Message;
			return false;
		}
		WriteFile(handle, hash, 16, out byteswritten, IntPtr.Zero);
		CloseHandle(handle);
		Alphaleonis.Win32.Filesystem.File.SetLastWriteTime(filename, modify);
		if (byteswritten == 16) return true;
		else return false;
	}

	public bool Detach(string filename) {
		try {
			DeleteFileW(filename + ":md5");
		} catch (Exception ex) {
			string buf = ex.Message;
			return false;
		}
		return true;
	}
}

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

namespace md5hashmt {
	public class md5hashmt {

		static string version = ParseVersion(); //"v1.0.9";
		static string GuiHeader =
@"╔═════════╦═══════════════════════════════════════╦═════════╦════════════╦══════════════════╗
║ Project ║                                       ║ Elapsed ║            ║ md5hashmt v1.0.0 ║
╠═════════╩════════════╦══════════════════════════╩═════════╩════════════╩══════════════════╣";
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

		public class FileListItem {
			public string Path;
			public long Size;
			public byte[] StoredHash;
			public byte[] ComputedHash;
		}

		static long MinFileSize = 0;
		static long MaxFileSize = Int64.MaxValue;
		static int MaxThreads = 1;
		static int LogLines = 10;
		static bool network = false;
		static int netport = 25;
		static bool ssl = false;
		static bool log = false;
		static string netuser = null;
		static string netpass = null;
		static string mailserver = null;
		static string mailfrom = null;
		static string mailto = null;
		static string logpath = null;
		static List<string> Roots;
		static Stopwatch totaltime;
		static string mailbody;
		static string logbody;
		enum MsgType { MSG_INFO, MSG_ALERT, MSG_WARNING, MSG_ERROR };
		static MsgType msgLevel;
		static string projectFile = "";
		static bool attachLog = false;
		static Status runtimeStatus = Status.Success;
		static MD5Alpha myMD5 = new MD5Alpha();
		static XYConsole.XYStringParam ProjectXY = new XYConsole.XYStringParam(12, 1, 37);
		static XYConsole.XYStringParam VersionXY = new XYConsole.XYStringParam(75, 1, 16);
		static XYConsole.XYStringParam TotalTimeXY = new XYConsole.XYStringParam(62, 1, 10);
		static XYConsole.XYStringParam MessageXY;
		static XYConsole myXYConsole;
		static bool exitRequested = false;
		static bool scanCompleted = false;
		static List<string> MatchNameList;
		static bool AlreadyNotified = false;
		static OperatingMode opMode = OperatingMode.Scan;

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
			if (type >= msgLevel) {
				switch (type) {
				case MsgType.MSG_INFO: color = ConsoleColor.Green; break;
				case MsgType.MSG_ALERT: color = ConsoleColor.Cyan; break;
				case MsgType.MSG_WARNING: color = ConsoleColor.Yellow; break;
				case MsgType.MSG_ERROR: color = ConsoleColor.Red; break;
				default: System.Console.ResetColor(); break;
				}
				if (display) myXYConsole.AddLog(msg, color);
				mailbody += msg + "\r\n";
				logbody += msg + "\r\n";
				System.Console.ResetColor();
			}
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

			if (!Alphaleonis.Win32.Filesystem.File.Exists(prjpath)) {
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
					network = true;
				} else if (buf == "[Log]") {
					mode = ProjectMode.Log;
					log = true;
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
							MatchNameList.Add(tokens[1]);
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
							mailto = tokens[1];
							break;
						case "from":
							mailfrom = tokens[1];
							break;
						case "server":
							mailserver = tokens[1];
							break;
						case "port":
							netport = Convert.ToInt32(tokens[1]);
							break;
						case "user":
							netuser = tokens[1];
							break;
						case "pass":
							netpass = tokens[1];
							break;
						case "ssl":
							if ((tokens[1] == "true") || (tokens[1] == "yes")) {
								ssl = true;
							} else {
								ssl = false;
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
							logpath = tokens[1];
							break;
						case "attach":
							if (tokens[1].ToLower() == "yes") {
								attachLog = true;
							}
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
				if (!Alphaleonis.Win32.Filesystem.Directory.Exists(Roots[i])) {
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
			LogMessage("[MODE] " + opMode.ToString(), MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] MinFileSize=" + MinFileSize, MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] MaxFileSize=" + MaxFileSize, MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] MaxThreads=" + MaxThreads, MsgType.MSG_ALERT);
			LogMessage("[PARAMETER] LogLines=" + LogLines, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] mailto: " + mailto, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] mailfrom: " + mailfrom, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] mailserver: " + mailserver, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] port: " + netport, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] userid: " + netuser, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] passwd: " + netpass, MsgType.MSG_ALERT);
			LogMessage("[NETWORK] SSL: " + (ssl ? "Yes" : "No"), MsgType.MSG_ALERT);
			LogMessage("[LOG] path: " + logpath, MsgType.MSG_ALERT);
			LogMessage("[LOG] attach: " + attachLog, MsgType.MSG_ALERT);
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
//					LogMessage("[DUMP] Rootlist#" + i + ", " + RootList[i].FileList.Count + " files");
					for (j = 0; j < RootList[i].FileList.Count; j++) {
						if (RootList[i].FileList[j].StoredHash == null) {
							tw.WriteLine(RootList[i].FileList[j].Path + "\tNo MD5" + "\t" + myMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + myMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
						} else if (RootList[i].FileList[j].StoredHash.SequenceEqual(zeroes)) {
							tw.WriteLine(RootList[i].FileList[j].Path + "\tMD5 Zeroes" + "\t" + myMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + myMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
						} else if (RootList[i].FileList[j].ComputedHash != null) {
							if (RootList[i].FileList[j].StoredHash.SequenceEqual(RootList[i].FileList[j].ComputedHash)) {
								tw.WriteLine(RootList[i].FileList[j].Path + "\tMD5 Match" + "\t" + myMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + myMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
							} else {
								tw.WriteLine(RootList[i].FileList[j].Path + "\tMD5 Mismatch" + "\t" + myMD5.GetHashString(RootList[i].FileList[j].StoredHash) + "\t" + myMD5.GetHashString(RootList[i].FileList[j].ComputedHash));
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
			runtimeStatus = Status.Error;
			if (totaltime != null) totaltime.Stop();
			Notify(runtimeStatus);
			System.Console.ResetColor();
			//			Console.OutputEncoding = System.Text.Encoding.Default;
			if (scanCompleted) {
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
			return match;
		}

		static void Notify(Status statusCode) {
			string logfile, dumpfile;
			string datepat = @"yyyy-MM-dd HH-mm-ss tt";
			string status;
			int i, j;

			if (AlreadyNotified) return;
			AlreadyNotified = true;
			switch (statusCode) {
			case Status.Success: status = " [Success]"; break;
			case Status.Warning: status = " [Warning]"; break;
			case Status.Error: status = " [Error]"; break;
			default: status = " [Success]"; break;
			}
			LogMessage("[INFO] Logfile size: " + logbody.Length + " bytes");
			if (network) {
				LogMessage("[INFO] Sending notification email");
				if (attachLog) {
					SendMail(mailserver, netport, ssl, netuser, netpass, mailfrom, mailto, "md5hashmt " + projectFile + status, mailbody);
				} else {
					SendMail(mailserver, netport, ssl, netuser, netpass, mailfrom, mailto, "md5hashmt " + projectFile + status, "See Log File for details");
				}
			}
			if (log) {
				logfile = logpath + "\\" + Alphaleonis.Win32.Filesystem.Path.GetFileNameWithoutExtension(projectFile) + " " + DateTime.Now.ToString(datepat) + status + ".log";
				LogMessage("[INFO] Saving log file " + logfile);
				SaveLog(logfile, logbody);
				LogMessage("[INFO] log file saved");
			}
			dumpfile = logpath + "\\" + Alphaleonis.Win32.Filesystem.Path.GetFileNameWithoutExtension(projectFile) + " " + DateTime.Now.ToString(datepat) + status + ".dump";
			LogMessage("[INFO] Saving dump file " + dumpfile);
			SaveDump(dumpfile, RootList);
			LogMessage("[INFO] dump file saved");
			System.Console.ResetColor();
		}

		static void OnProcessExit(object sender, EventArgs e) {

		}

		static void PrintHelp() {
			myXYConsole.AddLog("md5hashmt " + version + " - (C)2020 Bo-Yi Lin", ConsoleColor.Red);
			myXYConsole.AddLog("syntax: md5hashmt -p [prjpath] -m [mode] -l verbosity", ConsoleColor.Red);
			myXYConsole.AddLog("verbosity: INFO, WARNING, ERROR", ConsoleColor.Red);
			myXYConsole.AddLog("mode: SCAN, CALCULATE, ATTACH", ConsoleColor.Red);
		}

		static void PrintTime() {
			while (totaltime != null) {
				myXYConsole.WriteAt(TotalTimeXY, totaltime.Elapsed.ToString("G"), ConsoleColor.Cyan);
				if (Console.KeyAvailable) {
					if (Console.ReadKey(false).Key == ConsoleKey.Escape) {
						LogMessage("[WARNING] Exit requested", MsgType.MSG_WARNING);
						runtimeStatus = Status.Warning;
						exitRequested = true;
					}
				}
				Thread.Sleep(250);
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

		public class ScanMTParams {
			public string Path;
			public List<FileListItem> FileList;

			public ScanMTParams(string path) {
				FileList = new List<FileListItem>();
				Path = path;
			}
		};

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
				if (exitRequested) return;
				lock (paramLock) {
					myIndex = ScanIndex;
					if (myIndex >= RootList.Count()) return; // no more to do
					ScanIndex++;
				}
				Params = RootList[myIndex];
				myXYConsole.WriteAt(pathXY, RightJustify(Params.Path, 20), ConsoleColor.Green);
				Scan(Params.Path, Params.Path, pathXY, progXY, Params.FileList);
				myXYConsole.WriteAt(pathXY, "Idle", ConsoleColor.Green);
				myXYConsole.WriteAt(progXY, " ", ConsoleColor.Green);
			}
		}

		static void Scan(string root, string path,
			XYConsole.XYStringParam pathXY, XYConsole.XYStringParam progXY,
			List<FileListItem> fileList) {
			List<string> dirPaths, filePaths;
			string dirName, fileName;
			string child;
			Alphaleonis.Win32.Filesystem.FileInfo fi = null;
			byte[] zeroes = new byte[16];

			if (exitRequested) return;
			dirPaths = null;
			filePaths = null;
			myXYConsole.WriteAt(progXY, RightJustify(path, 66), ConsoleColor.Green);
			try {
				dirPaths = new List<string>(Alphaleonis.Win32.Filesystem.Directory.EnumerateDirectories(path));
			} catch (Exception ex) {
				LogMessage("[ERROR] Cannot list directories in " + path, MsgType.MSG_ERROR);
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
			}
			try {
				filePaths = new List<string>(Alphaleonis.Win32.Filesystem.Directory.EnumerateFiles(path));
			} catch (Exception ex) {
				LogMessage("[ERROR] Cannot list files in " + path, MsgType.MSG_ERROR);
				LogMessage("[ERROR] " + ex.Message, MsgType.MSG_ERROR);
				CleanExit();
			}
			foreach (string dirPath in dirPaths) {
				dirName = GetFolderName(dirPath);
				//				LogMessage("[DEBUG] " + dirName);
				if ((dirName == "$RECYCLE.BIN") | (dirName == "System Volume Information")) {
					LogMessage("[SKIP] " + dirName);
				} else if ((Alphaleonis.Win32.Filesystem.File.GetAttributes(path + "\\" + dirName) & System.IO.FileAttributes.ReparsePoint) == System.IO.FileAttributes.ReparsePoint) {
					LogMessage("[LINK] " + dirName);
				} else {
					child = path + "\\" + dirName;
					Scan(root, child, pathXY, progXY, fileList);
				}
			}
			foreach (string filePath in filePaths) {
				if (!MatchList(filePath.ToLower(), MatchNameList)) continue;
				System.IO.FileAttributes fileAttributes = System.IO.FileAttributes.Normal;

				fileName = Alphaleonis.Win32.Filesystem.Path.GetFileName(filePath);
				try {
					fileAttributes = Alphaleonis.Win32.Filesystem.File.GetAttributes(filePath);
				} catch (Exception ex) {
					LogMessage("[WARNING] " + ex.Message, MsgType.MSG_WARNING);
					continue;
				}
				if ((fileAttributes & System.IO.FileAttributes.ReparsePoint) == System.IO.FileAttributes.ReparsePoint) {
					LogMessage("[LINK] " + filePath);
				} else {
					FileListItem item = new FileListItem();
					try {
						fi = new Alphaleonis.Win32.Filesystem.FileInfo(filePath);
					} catch (Exception ex) {
						string buf = ex.Message;
						LogMessage("[WARNING] " + ex.Message, MsgType.MSG_WARNING);
						CleanExit();
					}
					if ((fi.Length >= MinFileSize) && (fi.Length < MaxFileSize)) {
						item.Path = filePath;
						item.StoredHash = myMD5.Read(filePath);
						if (item.StoredHash == null) {
							LogMessage("[WARNING] " + item.Path + " No MD5");
						} else if (item.StoredHash.SequenceEqual(zeroes)) {
							LogMessage("[WARNING] " + item.Path + " MD5 Zeroes");
						}
						item.Size = fi.Length;
						fileList.Add(item);
					}
				}
			}
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
				if (exitRequested) return;
				lock (paramLock) {
					myIndex = ComputeIndex;
					if (myIndex >= RootList.Count()) return; // no more to do
					ComputeIndex++;
				}
				Params = RootList[myIndex];
				myXYConsole.WriteAt(pathXY, RightJustify(Params.Path, 20), ConsoleColor.Green);
				Compute(Params.Path, Params.Path, pathXY, progXY, Params.FileList);
				myXYConsole.WriteAt(pathXY, "Idle", ConsoleColor.Green);
				myXYConsole.WriteAt(progXY, " ", ConsoleColor.Green);
			}
		}

		static void Compute(string root, string path,
			XYConsole.XYStringParam pathXY, XYConsole.XYStringParam progXY,
			List<FileListItem> fileList) {
			int i, p;
			byte[] zeroes = new byte[16];

			ProgressPrinter progress = new ProgressPrinter(myXYConsole, progXY, null);
			progress.Start();
			for (i = 0; i < fileList.Count; i++) {
				if (exitRequested) return;
				if (fileList[i].StoredHash == null) {
					if (opMode == OperatingMode.Attach) {
						fileList[i].ComputedHash = myMD5.Generate(fileList[i].Path);
						if (myMD5.Attach(fileList[i].Path, fileList[i].ComputedHash)) {
							LogMessage("[INFO] " + fileList[i].Path + " MD5 Attach");
						} else {
							LogMessage("[WARNING] " + fileList[i].Path + " MD5 Attach Failed");
						}
					} else {
						LogMessage("[INFO] " + fileList[i].Path + " No MD5");
					}
				} else if (fileList[i].StoredHash.SequenceEqual(zeroes)) {
					if (opMode == OperatingMode.Attach) {
						fileList[i].ComputedHash = myMD5.Generate(fileList[i].Path);
						myMD5.Detach(fileList[i].Path);
						if (myMD5.Attach(fileList[i].Path, fileList[i].ComputedHash)) {
							LogMessage("[INFO] " + fileList[i].Path + " MD5 Recompute");
						} else {
							LogMessage("[WARNING] " + fileList[i].Path + " MD5 Attach Failed");
						}
					} else {
						LogMessage("[WARNING] " + fileList[i].Path + " MD5 Zeros");
					}
				} else if (opMode == OperatingMode.Verify) {
					fileList[i].ComputedHash = myMD5.Generate(fileList[i].Path);
					if (!fileList[i].StoredHash.SequenceEqual(fileList[i].ComputedHash)) {
						LogMessage("[WARNING] " + fileList[i].Path + " MD5 Mismatch", MsgType.MSG_WARNING);
					}
				}
				p = (i * 100) / fileList.Count;
				progress.Print(p);
			}
			progress.Stop();
		}

		static void Main(string[] args) {
			int i, argn;
			Thread timeThread;
			int c;

			MessageXY = new XYConsole.XYStringParam(2, 10, 89);
			myXYConsole = new XYConsole(20, MessageXY, LogLines);
			if (args.Length == 0) {
				LogMessage("[ERROR] No arguments specified", MsgType.MSG_ERROR, true);
				PrintHelp();
				CleanExit();
			}
			msgLevel = MsgType.MSG_INFO;
			AppDomain.CurrentDomain.ProcessExit += new EventHandler(OnProcessExit);
			Console.OutputEncoding = System.Text.Encoding.UTF8;
			for (c = 0; c < args.Length; c++) {
				if (args[c] == "-p") {
					projectFile = args[c + 1];
					c++;
				} else if (args[c] == "-l") {
					switch (args[c + 1].ToLower()) {
					case "info": msgLevel = MsgType.MSG_INFO; break;
					case "alert": msgLevel = MsgType.MSG_ALERT; break;
					case "warning": msgLevel = MsgType.MSG_WARNING; break;
					case "error": msgLevel = MsgType.MSG_ERROR; break;
					default: break;
					}
					c++;
				} else if (args[c] == "-m") {
					switch (args[c + 1].ToLower()) {
					case "scan": opMode = OperatingMode.Scan; break;
					case "calulate": opMode = OperatingMode.Verify; break;
					case "attach": opMode = OperatingMode.Attach; break;
					default: break;
					}
				}
			}

			if (projectFile == "") {
				myXYConsole.Finish(); totaltime = null;
				LogMessage("[ERROR] No project file specified", MsgType.MSG_ERROR, true);
				PrintHelp();
				CleanExit();
			}
			Roots = new List<string>();
			LoadProject(projectFile);
			MessageXY = new XYConsole.XYStringParam(2, 4 + MaxThreads, 89);
			myXYConsole = new XYConsole(5 + MaxThreads + LogLines, MessageXY, LogLines);
			Console.Clear();
			myXYConsole.PrintRaw(0, 0, GuiHeader, ConsoleColor.Yellow);
			for (i = 0; i < MaxThreads; i++) {
				myXYConsole.PrintRaw(0, 3 + i, GuiThreadLine, ConsoleColor.Yellow);
			}
			myXYConsole.PrintRaw(0, 3 + MaxThreads, GuiSpacer, ConsoleColor.Yellow);
			for (i = 0; i < LogLines; i++) {
				myXYConsole.PrintRaw(0, 4 + MaxThreads + i, GuiLogLine, ConsoleColor.Yellow);
			}
			myXYConsole.PrintRaw(0, 4 + MaxThreads + LogLines, GuiFooter, ConsoleColor.Yellow);
			myXYConsole.WriteAt(VersionXY, "md5hashmt " + version, ConsoleColor.Cyan);
			CheckProject();
			RootList = new List<ScanMTParams>();
			for (i = 0; i < Roots.Count; i++) {
				ScanMTParams Params = new ScanMTParams(Roots[i]);
				RootList.Add(Params);
			}
			totaltime = new Stopwatch();
			totaltime.Start();
			timeThread = new Thread(PrintTime);
			timeThread.Start();
			myXYConsole.WriteAt(ProjectXY, projectFile, ConsoleColor.Cyan);
			LaunchScanMT();
			LaunchComputeMT();
			timeThread.Abort();
			Notify(runtimeStatus);
			totaltime.Stop();
			totaltime = null;
			myXYConsole.Finish();
			System.Console.ResetColor();
		}
	}
}
