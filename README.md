# folder-to-text-file
convert folders to text files
📦 Folder Export/Import Tool – Powerful & Flexible Data Packaging

A lightweight yet powerful Python tool that lets you export any folder into a single .txt or .json file and later import it back with the full original file/folder structure restored.
It supports optional compression, AES-256 password encryption, ignore patterns, and a progress bar for a smooth experience.

It can also be used to convert your entire programming project (folder + files) into a well-structured text format, making it easy to send to AI tools for bug fixing and code improvements by intelligent models.

Additionally, it helps you combine all your files and subfolders into one single text file, reducing clutter and making storage or sharing much simpler and more efficient.

The tool works in both interactive mode and command-line mode, making it ideal for developers, researchers, and programmers who need a clean and portable way to package, restore, or review their files — even with AI assistance.

✨ Key Features:

Export entire folders into a single text or JSON file.

Import back with full folder structure restoration.

Convert programming projects into AI-friendly text format.

Merge all files and subfolders into one single text file for easy storage/sharing.

Optional:

Gzip compression for smaller size.

AES-256 encryption for secure storage.

Ignore specific files/folders/extensions using glob patterns.

Progress bar for long operations.

Cross-platform support (Windows, Linux, macOS).
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
📌 Examples of Using the Tool
1. Interactive Mode
python folder-to-txt-pro.py


Opens the interactive menu to Export or Import a folder.

2. Export a Folder to TXT (No Compression, No Encryption)
python folder-to-txt-pro.py export my_project output.txt

3. Export with Gzip Compression
python folder-to-txt-pro.py export my_project output.txt --compress

4. Export with AES-256 Password Protection
python folder-to-txt-pro.py export my_project output.txt --password "MySecret123"

5. Export and Ignore Certain Files
python folder-to-txt-pro.py export my_project output.txt --ignore "*.png *.log"

6. Import Back to a Folder
python folder-to-txt-pro.py import output.txt restored_folder

7. Import a Password-Protected File
python folder-to-txt-pro.py import output.txt restored_folder --password "MySecret123"


💡 Tip: You can combine options:

python folder-to-txt-pro.py export my_project output.txt --compress --password "SecurePass!" --ignore "*.tmp *.bak"
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
ex
┌──(ouassim㉿archlinux) (global)-[~/Projects/python-project/folder to txt]
├─[14:41 2025-08-15]
└─✔ $ python folder-to-txt-pro.py
Folder <-> TXT/JSON Converter
------------------------------
1) Export folder
2) Import archive
3) Help
4) Exit
Select an option: 1
Enter folder path to export: /home/ouassim/Downloads/brave-new-tab1/
Output format [txt/json] (default: txt): txt
Enter output file (e.g., backup.txt): bravexx.txt
Enable gzip compression for file payloads? [y/N]: N
Enable AES-256-GCM password encryption for all files? [y/N]: N
Ignore patterns (space-separated, glob allowed; leave empty for none): 
Show progress bar? [Y/n]: Y
Exported to bravexx.txt
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   📌 Usage Simulation
📂 Target folder before export
my_project/
├── main.py
├── config.json
├── icon.png
├── utils/
│   ├── helper.py
│   └── notes.txt

📜 Export without compression or password
$ python folder-to-txt-pro.py export my_project output.txt
Exporting folder: my_project
Compression: None
Password: None
Ignore patterns: None
[##########] 100% Done!
Export completed → output.txt

📖 Viewing the output file using cat
$ cat output.txt


Result (shortened for display):

my_project
├── main.py
│   print("Hello, World!")
│   print("This is main script")
├── config.json
│   {
│       "version": "1.0",
│       "debug": true
│   }
├── icon.png
│   [BINARY DATA: PNG IMAGE, 1024 bytes]
├── utils/helper.py
│   def greet(name):
│       return f"Hello {name}"
├── utils/notes.txt
│   TODO:
│   - Refactor greet function
│   - Add more features

📜 Export with compression and password
$ python folder-to-txt-pro.py export my_project output.txt --compress --password "Secret123"
Exporting folder: my_project
Compression: gzip
Password: [ENABLED]
Ignore patterns: None
[##########] 100% Done!
Export completed → output.txt (compressed & encrypted)

📖 Viewing the content after compression and encryption
$ cat output.txt


The result will be compressed and encrypted data, shown as unreadable symbols:

H4sIAAAAAAAA/3yQwU7DMAyF9z4Fzd...
...(binary encrypted data)...
