using Gtk;

public class Main {

	public const string[] iconData = {
		"16 16 102 2",
		"  	c None",
		". 	c #4E8DC0",
		"+ 	c #4A86BA",
		"@ 	c #4883B4",
		"# 	c #447EAD",
		"$ 	c #4078A7",
		"% 	c #3C719E",
		"& 	c #376896",
		"* 	c #4C8ABC",
		"= 	c #FFFFFF",
		"- 	c #457FAF",
		"; 	c #4179A8",
		"> 	c #3E74A2",
		", 	c #3A6F9B",
		"' 	c #366994",
		") 	c #4985B7",
		"! 	c #4680B1",
		"~ 	c #427BAA",
		"{ 	c #3E75A3",
		"] 	c #3B709D",
		"^ 	c #376A96",
		"/ 	c #4C8ABF",
		"( 	c #4885B6",
		"_ 	c #437DAD",
		": 	c #3D74A1",
		"< 	c #396C96",
		"[ 	c #366690",
		"} 	c #386C97",
		"| 	c #5291C6",
		"1 	c #4F8DC1",
		"2 	c #4B88BB",
		"3 	c #447DAD",
		"4 	c #4078A6",
		"5 	c #3D73A0",
		"6 	c #396D99",
		"7 	c #FFE255",
		"8 	c #FDDD4A",
		"9 	c #F9D53E",
		"0 	c #508FC3",
		"a 	c #4C89BC",
		"b 	c #4884B5",
		"c 	c #326087",
		"d 	c #FFDE4B",
		"e 	c #FFDA41",
		"f 	c #FDD536",
		"g 	c #4D8BBE",
		"h 	c #4680B0",
		"i 	c #3B709C",
		"j 	c #356892",
		"k 	c #ECCE45",
		"l 	c #FFDA42",
		"m 	c #FFD637",
		"n 	c #FFD32D",
		"o 	c #4A87B9",
		"p 	c #4781B2",
		"q 	c #437CAB",
		"r 	c #3F76A5",
		"s 	c #366993",
		"t 	c #FDD941",
		"u 	c #FFD738",
		"v 	c #FFCF23",
		"w 	c #4681B2",
		"x 	c #366791",
		"y 	c #F2E16E",
		"z 	c #FDE96A",
		"A 	c #FFE661",
		"B 	c #FFE357",
		"C 	c #FFDF4D",
		"D 	c #FFDB42",
		"E 	c #FFD32E",
		"F 	c #FFCF24",
		"G 	c #FDCB1B",
		"H 	c #437DAE",
		"I 	c #F5E36F",
		"J 	c #FFEB6C",
		"K 	c #FFE761",
		"L 	c #FFDB43",
		"M 	c #FFD739",
		"N 	c #FFCC1C",
		"O 	c #F3C11A",
		"P 	c #3D73A2",
		"Q 	c #3A709C",
		"R 	c #FFE762",
		"S 	c #FFE358",
		"T 	c #FFDF4E",
		"U 	c #FFD32F",
		"V 	c #E8C73D",
		"W 	c #EBC534",
		"X 	c #EBC22A",
		"Y 	c #EBBE21",
		"Z 	c #EBBB18",
		"` 	c #FFDB44",
		" .	c #FFD73A",
		"..	c #FFD330",
		"+.	c #FFD025",
		"@.	c #FDDE4E",
		"#.	c #FFD83A",
		"$.	c #FFD430",
		"%.	c #FFD026",
		"&.	c #FAD339",
		"*.	c #FDD22F",
		"=.	c #FAC719",
		"        . + @ # $ % &           ",
		"        * = - ; > , '           ",
		"        ) ! ~ { ] ^ '           ",
		"    / ( _ : < [ } ' '           ",
		"| 1 2 @ 3 4 5 6 ' ' '   7 8 9   ",
		"0 a b - ; : , ' ' ' c   d e f   ",
		"g ) h ~ { i ^ ' j c   k l m n   ",
		"o p q r s             t u n v   ",
		"w 3 4 x   y z A B C D u E F G   ",
		"H ; :   I J K B C L M E F N O   ",
		"  P Q   J R S T L M U F N N     ",
		"        R S T V W X Y Z Z       ",
		"        S T `  ...+.N           ",
		"        @.` #.$.%.= G           ",
		"          &.*.%.N =.            ",
		"                                "};


	class AppStatusIcon : Window {
		private StatusIcon trayicon;
		private Menu menuSystem;
		private Pid pid;

		public AppStatusIcon() {
			/* Create tray icon */
			trayicon = new StatusIcon.from_pixbuf(new Gdk.Pixbuf.from_xpm_data(iconData));
			//trayicon.set_tooltip_text("GoAgent Tray");
			trayicon.set_visible(true);
			trayicon.activate.connect(log_clicked);
			create_menuSystem();
			trayicon.popup_menu.connect(menuSystem_popup);	
			create_subprocess();
		}


		void main_quit() {
			Posix.kill ((int)pid, 9);
			Gtk.main_quit();
		}

		/* Create menu for right button */
		public void create_menuSystem() {
			menuSystem = new Menu();
			var menuLog = new  MenuItem.with_mnemonic("_About");
			menuLog.activate.connect(log_clicked);
			menuSystem.append(menuLog);
			var menuQuit = new MenuItem.with_mnemonic("_Quit");
			menuQuit.activate.connect(main_quit);
			menuSystem.append(menuQuit);
			menuSystem.show_all();
		}

		void on_async_exit(Pid pid, int status)
		{
			Process.close_pid(pid);
		}

		/* Create menu for right button */
		public void create_subprocess() {
			string[] runme = { "python", "proxy.py", null};
			try {
				Process.spawn_async (".", runme, null, SpawnFlags.SEARCH_PATH|SpawnFlags.DO_NOT_REAP_CHILD|SpawnFlags.STDOUT_TO_DEV_NULL|SpawnFlags.STDERR_TO_DEV_NULL, null, out pid);
				ChildWatch.add (pid, on_async_exit);
			}
			catch (Error e) {
				stderr.printf ("Could not load UI: %s\n", e.message);
				//(new Gtk.MessageDialog(this, Gtk.DialogFlags.MODAL, Gtk.MessageType.ERROR,Gtk.ButtonsType.OK,"proxy.py load failed: \n"+e.message)).run();
			}
		}

		/* Show popup menu on right button */
		private void menuSystem_popup(uint button, uint time) {
			menuSystem.popup(null, null, null, button, time);
		}

		private void log_clicked() {
			var about = new AboutDialog();
			about.set_version("1.0");
			about.set_program_name("GoAgent");
			string comments = "Unkdown Error";
			try {
				string[] cmd = {"python", "-c", "import sys,os,ConfigParser;config=ConfigParser.ConfigParser();config.read('proxy.ini');openssl=('Disabled','Enabled')[any(os.path.isdir(x+'/OpenSSL') for x in sys.path)];addr='%s:%s'%(config.get('listen','ip'),config.get('listen','port'));appid=config.get('gae','appid');mode=config.get('google','prefer');status=('Stopped', 'Running')[len([x for x in os.popen('ps -ef').read().splitlines() if x.endswith('python proxy.py')])>=1];sys.stdout.write('\\n'.join(('OpenSSL : '+openssl, 'Listen : '+addr,'Mode : '+mode,'APPID : '+appid, 'Status : ' +status)))"};
				Process.spawn_sync (".", cmd, null, SpawnFlags.SEARCH_PATH, null, out comments, null, null);
                        }
			catch (Error e) {
				stderr.printf ("Could not load UI: %s\n", e.message);
                                comments = "GoAgent 1.0 Stable";
			}
			about.set_comments(comments);
			//about.set_copyright("copyright gogent(2011-2012)");
			about.run();
			about.hide();;
		}

	}

	public static int main (string[] args) {
		Gtk.init(ref args);
		var App = new AppStatusIcon();
		App.hide();
		Gtk.main();
		return 0;
	}
} 