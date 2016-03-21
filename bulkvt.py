#!/usr/bin/python
#The MIT License (MIT)
#Copyright (c) 2016 Jimmy Tuong (tuongj@gmail.com)
#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

__author__ = "Jimmy Tuong"
__license__ = "MIT"
__version__ = "1.1"
__email__ = "tuongj@gmail.com"

import urllib.request, urllib.parse
import csv, json, hashlib, os, webbrowser
from tkinter import *
from tkinter.ttk import *
from tkinter import filedialog, messagebox


class VirusTotal():
	def __init__(self):
		self.reportfile = "https://www.virustotal.com/vtapi/v2/file/report"
		self.reporturl = "http://www.virustotal.com/vtapi/v2/url/report"

		# To be implemented in the future
		# self.reportdomain = "http://www.virustotal.com/vtapi/v2/domain/report"
		# self.reportip = "http://www.virustotal.com/vtapi/v2/ip-address/report"
		
		self.proxy = {}	# Insert proxy here i.e. {"http":"http://www.example.com:80"} (Optional)
						
	def read_apikey(self):
		filepath = os.path.dirname(os.path.realpath(__file__)) + "\\bulkvt_key.txt"
		
		with open(filepath, "r") as file:
			for line in file.readlines():
				self.apikey = line
					
	def has_apikey(self):
		try:
			if len(self.apikey) >= 64:
				return True
		except Exception:
			return False
		
	def format_list(self, filepath, data_type=None):
		parameters = {}
		hash_templist = []
		url_templist = []
		
		with open(filepath, "r") as file:
			
			if filepath.endswith(".csv"):
				reader = csv.reader(file)
		
				for row in reader:
					x = "\n".join(row)
		
					for line in x.splitlines():
						if self.is_hash(line.strip()):
							hash_templist.append(line)
						elif self.is_url(line.strip()):
							url_templist.append(line)
		
			elif filepath.endswith(".txt") or filepath.endswith(".log"):
				for line in file.readlines():
					if self.is_hash(line.strip()):
						hash_templist.append(line.strip())
					elif self.is_url(line.strip()):
						url_templist.append(line)

		
		if len(hash_templist) > 0 and data_type == "Hash":
			hash_values = ", ".join(str(i) for i in hash_templist)
			parameters["hash"] = hash_values
		if len(url_templist) > 0 and data_type == "URL":
			url_values = "\n".join(str(i) for i in url_templist)
			parameters["url"] = url_values
		
		parameters["apikey"] = self.apikey
		
		return parameters
		
	def format_value(self, data_input):
		parameters = {}
		
		if isinstance(data_input, list):
			values = ", ".join(str(i) for i in data_input)
			parameters["hash"] = values

		elif self.is_hash(data_input):
			parameters["hash"] = data_input
		
		elif self.is_url(data_input):
			parameters["url"] = data_input

		parameters["apikey"] = self.apikey
				
		return parameters
		
	def get_file_list(self, dir):
		items = []
		
		for root, dirs, files in os.walk(dir, topdown=True, onerror=None, followlinks=False):
			for file in files:
				file_path = os.path.abspath(os.path.join(root, file))
				items.append(file_path)
		
		return items
		
	def scan_lookup(self, parameters):
		
		proxy_handler = urllib.request.ProxyHandler(self.proxy)
		opener = urllib.request.build_opener(proxy_handler)
		urllib.request.install_opener(opener)
		
		hash_status = False
		url_status = False
		
		if "hash" in parameters:
			if "resource" in parameters:
				del parameters["resource"]

			parameters["resource"] = parameters.pop("hash")
			
			hash_data = urllib.parse.urlencode(parameters)
			hash_data = hash_data.encode("ascii")
		
			hash_request = urllib.request.urlopen(self.reportfile, hash_data)
			hash_response = hash_request.read().decode("utf-8")

			hash_report = json.loads(hash_response)

			hash_status = True

		if "url" in parameters:
			if "resource" in parameters:
				del parameters["resource"]

			parameters["resource"] = parameters.pop("url")
			url_data = urllib.parse.urlencode(parameters)
			url_data = url_data.encode("ascii")
			
			url_request = urllib.request.urlopen(self.reporturl, url_data)
			url_response = url_request.read().decode("utf-8")

			url_report = json.loads(url_response)
		
			url_status = True

		if hash_status:
			return hash_report
		elif url_status:
			return url_report
		
	def output_file(self, response, output, files=None, data_type="Hash"):
		templist = []

		hash_header = ["MD5", "SHA1", "SHA256", "Positive", "Total", "Scan Date", "Reference"]
		url_header = ["URL", "Positive", "Total", "Scan Date", "Reference"]
		
		hash_keys = ["md5","sha1", "sha256", "positives","total","scan_date", "permalink"]
		url_keys = ["url", "positives", "total", "scan_date", "permalink"]
		
		if data_type == "Hash":
			current_keys = hash_keys[:]
			current_header = hash_header[:]
		elif data_type == "URL":
			current_keys = url_keys[:]
			current_header = url_header[:]
				
		if files is not None:
			for idx, item in enumerate(response):
				item["file path"] = files[idx]
				item["resource"] = item["file path"]
			current_header.insert(0,"File")
			current_keys.insert(0,"file path")
		
		with open(output, "w", newline="\n") as file:
				if output.endswith(".csv"):
					csvfile = csv.writer(file)
					csvfile.writerow(current_header)
				
					for item in response:
						if item["response_code"] == 1:
							for key in current_keys:
								templist.append(item[key])
							
							csvfile.writerow(templist)

							templist[:] = []
						else:
							error = " ".join([item["resource"], "not found. The file/url you are looking for is not in the database."])
							csvfile.writerow([error])
			
				elif output.endswith(".txt") or output.endswith(".log"):
					file.write(",".join(current_header))
					file.write("\r\n")
				
					for item in response:
						if item["response_code"] == 1:
							for key in current_keys:
								templist.append(item[key])
							
							joinitem = ",".join(str(i) for i in templist)
								
							file.write(joinitem)
							file.write("\r\n")
							
							templist[:] = []
			
						else:
							error = " ".join([item["resource"], "not found. The file/url you are looking for is not in the database.\r\n"])
							file.write(error)
	
	def output_result(self, item):
		templist = []

		hash_header = ["MD5", "SHA1", "SHA256", "Positive", "Total", "Scan Date", "Reference"]
		url_header = ["URL", "Positive", "Total", "Scan Date", "Reference"]

		hash_keys = ["md5","sha1", "sha256", "positives","total","scan_date", "permalink"]
		url_keys = ["url", "positives", "total", "scan_date", "permalink"]

		if self.is_hash(item["resource"]):
			current_keys = hash_keys[:]
			current_header = hash_header[:]
		elif self.is_url(item["resource"]):
			current_keys = url_keys[:]
			current_header = url_header[:]

		if item["response_code"] == 1:
			LIST = [item[i] for i in current_keys]

			for i in range(len(current_header)):
				single_result = current_header[i]+": {"+str(i)+"}"
				templist.append(single_result)
			merge_result = "\n".join(templist)
			
			result = merge_result.format(*LIST)

		elif item["response_code"] == 0:
			result = "{0} not found. The file/url you are looking for is not in the database.".format(item["resource"])

		return result
		
	def hash_file(self, files):
		BLOCKSIZE = 65536
		items = []
		hash = []
		
		if isinstance(files, str):
			items.append(files)
		else:
			items = files.copy()
		
		md5 = hashlib.md5()
		
		for item in items:
			with open(item, "rb") as f:
				buffer_size = f.read(BLOCKSIZE)
				while len(buffer_size) > 0:
					md5.update(buffer_size)
					buffer_size = f.read(BLOCKSIZE)
		
			hash.append("{0}".format(md5.hexdigest()))
			if isinstance(files, list):
				md5 = hashlib.md5()
				
		return hash
	
	def is_hash(self, item):
		num = [32, 40, 64]
		
		if len(item) in num:
			match_obj = re.match("^[a-fA-F0-9]*$", item)
			if match_obj:
				return True
		
		return False

	def is_ip(self, item):
		match_obj = re.match("(\d{1-3}.\d{1-3}.\d{1-3}.\d{1-3})", item)

		if match_obj:
			return True
		else:
			return False

	def is_domain(self, item):
		match_obj = re.match("(^\w+://\S+)", item)

		if not match_obj:
			item = "http://" + item
		
		parsed = urllib.parse.urlparse(item)

		if parsed[2] == "/" or len(parsed[2]) == 0:
			return True
		else:
			return False

	def is_url(self, item):
		match_obj1 = re.match("^\w+://\S+", item)

		if not match_obj1:
			item = "http://" + item
		
		parsed = urllib.parse.urlparse(item)
		
		match_obj2 = re.match("((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}", parsed[1])
		match_obj3 = re.match('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', parsed[1])

		if match_obj2 or (match_obj3 and len(parsed[2]) > 1):
			return True
		else:
			return False
		

class App(VirusTotal):
	def __init__(self, master):
		VirusTotal.__init__(self)
		
		self.master = master
		self.frame = Frame(master)
		
		for r in range(1,5):
		 	self.frame.rowconfigure(r, weight=1)
		for c in range(1,3):
		 	self.frame.columnconfigure(c, weight=1)
		
		self.initialize_widgets()

		self.frame.pack(fill=X, expand=YES)
	
	def initialize_widgets(self):
		self.setpadx = 5
		self.setpady = 5

		self.menu_widget()
		self.single_frame_widget()

	def menu_widget(self):
		menu = Menu(self.master)
		self.master.config(menu=menu)
		
		menu_file = Menu(menu, tearoff=0)
		menu_file.add_command(label="API Key", command=self.prompt_apikey)
		menu_file.add_separator()
		menu_file.add_command(label="Exit", command=self.client_exit)
		menu.add_cascade(menu=menu_file, label="File")

		menu_help = Menu(menu, tearoff=0)
		menu_help.add_command(label="About", command=self.prompt_about)
		menu.add_cascade(menu=menu_help, label="Help")

	def select_mode(self, frame, select_type=None):
		self.submit_type = IntVar()

		self.submit_label = Label(frame, text="Mode:")
		self.submit_label.grid(row=0, padx=self.setpadx, sticky="E")

		self.single_radiotype = Radiobutton(frame, text="Single", variable=self.submit_type, value=0, command=self.single_frame_widget)
		self.single_radiotype.grid(row=0, column=1, padx=self.setpadx, sticky="NSWE")

		self.bulk_radiotype = Radiobutton(frame, text="Bulk", variable=self.submit_type, value=1, command=self.bulk_frame_widget)
		self.bulk_radiotype.grid(row=0, column=2, padx=self.setpadx, sticky="NSWE")

		self.directory_radiotype = Radiobutton(frame, text="Directory", variable=self.submit_type, value=2, command=self.directory_frame_widget)
		self.directory_radiotype.grid(row=0, column=3, padx=self.setpadx, sticky="NSWE")

	def input_widget(self, frame, row_input=1):
		input_frame = Frame(frame)
		input_frame.grid()

		self.input = Label(frame, text="Source:")
		self.input.grid(row=row_input, column=0, padx=self.setpadx, sticky="E")
		
		self.input_entry = Entry(frame, width=50)
		self.input_entry.grid(row=row_input, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky="NSWE")
		
		self.input_button = Button(frame, text="...", command=self.input_action)
		self.input_button.grid(row=row_input, column=6, sticky="E")

		Separator(frame, orient=HORIZONTAL).grid(row=row_input+1, columnspan=8, pady=self.setpady, sticky="WE")
	
	def resize_widget(self, frame):
		for r in range(1,4):
			frame.rowconfigure(r, weight=1)
		for c in range(1,3):
			frame.columnconfigure(c, weight=1)

		frame.pack(fill=X, expand=YES)

	def input_action(self):
		FILETYPES1 = [("All files", ".*"),
				("Batch files", ".bat"),
				("Dynamic Link Library files", ".dll"),
				("JavaScript files", ".js"),
				("MS-DOS program", ".com"),
				("Executable files", ".exe"),
				("Screen saver files", ".scr"),
				("VBScript files", ".vb;*.vbs")]
		FILETYPES2 = [("All files", ".csv;*.log;*.txt"),
						("CSV files", ".csv"),
						("Log files",".log"),
						("Text files", ".txt")]
		selected_type = self.submit_type.get()

		if selected_type == 0:
			dialog = filedialog.askopenfilename(defaultextension=".*", filetypes=FILETYPES1)
		elif selected_type == 1:
			dialog = filedialog.askopenfilename(filetypes=FILETYPES2)
		elif selected_type == 2:
			dialog = filedialog.askdirectory()
		
		self.input_entry.delete(0, END)
		self.input_entry.insert(END, dialog)

	def single_frame_widget(self):
		self.remove_all_frame_widget()

		self.single_frame = Frame(self.frame)
		self.single_frame.grid()

		self.select_mode(self.single_frame)
		self.submit_type.set(0)
		self.input_widget(self.single_frame)

		self.input_entry.insert(0, "Enter hash, url, or select a file...")
		self.input_entry.bind("<Button-1>", self.on_entry_click)

		self.output = Label(self.single_frame, text="Result:")
		self.output.grid(row=3, column=0, sticky="E")
		

		self.output_entry = Text(self.single_frame, width=50, height=11)
		self.output_entry.grid(row=3, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky="NSWE")
		
		
		'''# self.scrollbar = Scrollbar(frame, orient=VERTICAL, command=self.output_entry.yview)
		# self.scrollbar.grid(row=3, column=5, sticky="NS")
		
		# self.output_entry["yscrollcommand"] = self.scrollbar.set'''

		self.submit_button = Button(self.single_frame, text="Submit", command=self.submit_action)
		self.submit_button.grid(row=4, column=1, columnspan=2, pady=self.setpady, sticky="NSWE")
		
	def bulk_frame_widget(self):
		self.bulk_type = StringVar()
		
		self.remove_all_frame_widget()

		self.bulk_frame = Frame(self.frame)
		self.bulk_frame.grid()
		
		self.select_mode(self.bulk_frame)
		self.submit_type.set(1)

		self.bulk_select_label = Label(self.bulk_frame, text="Data Type:")
		self.bulk_select_label.grid(row=1, column=0, padx=self.setpadx, sticky="E")

		self.bulk_select_type = Combobox(self.bulk_frame, width=5, textvariable=self.bulk_type)
		self.bulk_select_type.grid(row=1, column=1, padx=self.setpadx, pady=self.setpady, sticky="NSWE")
		self.bulk_select_type.state(['readonly'])
		self.bulk_select_type['values'] = ('Hash', 'URL')
		self.bulk_select_type.set('Hash')

		self.input_widget(self.bulk_frame, row_input=2)

		self.output = Label(self.bulk_frame, text="Destination:")
		self.output.grid(row=4, column=0, sticky="E")
	
		self.output_entry = Entry(self.bulk_frame, width=50)
		self.output_entry.grid(row=4, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky="NSWE")
		
		self.output_button = Button(self.bulk_frame, text="...", command=self.output_file_action)
		self.output_button.grid(row=4, column=6, sticky="E")

		self.submit_button = Button(self.bulk_frame, text="Submit", command=self.submit_action)
		self.submit_button.grid(row=5, column=1, columnspan=2, pady=self.setpady, sticky="NSWE")
		
	def directory_frame_widget(self):
		self.remove_all_frame_widget()

		self.directory_frame = Frame(self.frame)
		self.directory_frame.grid()

		self.select_mode(self.directory_frame)
		self.submit_type.set(2)
		self.input_widget(self.directory_frame)

		self.output = Label(self.directory_frame, text="Destination:")
		self.output.grid(row=3, column=0, sticky="E")
	
		self.output_entry = Entry(self.directory_frame, width=50)
		self.output_entry.grid(row=3, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky="NSWE")
		
		self.output_button = Button(self.directory_frame, text="...", command=self.output_file_action)
		self.output_button.grid(row=3, column=6, sticky="E")

		self.submit_button = Button(self.directory_frame, text="Submit", command=self.submit_action)
		self.submit_button.grid(row=4, column=1, columnspan=2, pady=self.setpady, sticky="NSWE")

	def remove_all_frame_widget(self):
		try:
			self.single_frame.grid_forget()
		except Exception:
			pass

		try:
			self.bulk_frame.grid_forget()
		except Exception:
			pass

		try:
			self.directory_frame.grid_forget()
		except Exception:
			pass
	
	def prompt_apikey(self):
		top = Toplevel(self.frame)
		
		label = Label(top, text="Enter VirusTotal API Key:")
		label.grid(row=0, padx=self.setpadx, pady=self.setpady, sticky="NS")
		
		self.key_entry = Entry(top, width=70)
		self.key_entry.grid(row=1, padx=self.setpadx, pady=self.setpady, sticky="NSWE")
		
		button = Button(top, text="Submit", command=lambda: self.create_apikey(top))
		button.grid(row=2, padx=self.setpadx, pady=self.setpady, sticky="NS")

	def create_apikey(self, top):
		key = self.key_entry.get().replace(" ","")
		filepath = os.path.dirname(os.path.realpath(__file__)) + "\\bulkvt_key.txt"
		
		if len(key) < 64:
			messagebox.showerror(message="Your API key is invalid. Please insert a valid API key.")
		else:
			with open(filepath, "w+") as file:
				file.write(key)
			messagebox.showinfo(message="Your API key has been saved in\n" + filepath)
		top.destroy()

	def prompt_about(self):
		top = Toplevel(self.frame)

		label1 = Label(top, width=25, font=("Helvetica 12 bold"), anchor=CENTER, justify=CENTER, text="BulkVT")
		label1.grid()

		label2 = Label(top, font=("Helvetica 8"), foreground="#0000ff", cursor="hand2", anchor=CENTER, justify=CENTER, text="https://github.com/tuongj/BulkVT")
		label2.grid()
		label2.bind("<Button-1>", self.open_hyperlink)

		label3 = Label(top, font=("Helvetica 8"), anchor=CENTER, justify=CENTER, text="Developed by\nJimmy Tuong\n\nMIT License\nVersion "+__version__)
		label3.grid()

		button = Button(top, text="OK", command=top.destroy)
		button.grid(pady=self.setpady)

	def open_hyperlink(self, event):
		webbrowser.open_new(r"https://github.com/tuongj/BulkVT")
	
	
	def client_exit(self):
		sys.exit()
		
	def on_entry_click(self, event):
		str = self.input_entry.get()
		
		if str == "Enter hash, url, or select a file...":
			self.input_entry.delete(0, END)
		
	def output_file_action(self):
		FILETYPES3 = [("CSV files", ".csv"),
					("Log files",".log"),
					("Text files", ".txt")]

		dialog = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=FILETYPES3)
		
		self.output_entry.delete(0, END)
		self.output_entry.insert(END, dialog)
		
	def submit_action(self):
		data_input = self.input_entry.get().strip()
		selected_type = self.submit_type.get()
				
		try:
			self.read_apikey()
			output = self.output_entry.get()
			bulk_type = self.bulk_type.get()
		except Exception:
			pass
		
		if not self.has_apikey():
			messagebox.showerror(message="You need an API key.\nClick on the menu File > API Key to insert your API Key.")
		#elif not self.output_entry.get():
			#messagebox.showinfo(message="You must select an output path!")
		#elif not self.input_entry.get():
			#messagebox.showinfo(message="You must select a source!")
		
		elif selected_type == 0:
			try:
				if not self.is_hash(data_input) and not self.is_url(data_input):
					data_input = self.hash_file(data_input)
									
				value = self.format_value(data_input)
				response = self.scan_lookup(value)
				result = self.output_result(response)
				
			except Exception as e:
				result = e
			finally:
				self.output_entry.delete(1.0, END)
				self.output_entry.insert(END, result)
				
		elif selected_type == 1:
			scan = self.format_list(data_input, data_type=bulk_type)
			response = self.scan_lookup(scan)
			self.output_file(response, output, data_type=bulk_type)
			
			messagebox.showinfo(message="BulkVT lookup is complete!")
			
		elif selected_type == 2:
			files = self.get_file_list(data_input)
			data_input = self.hash_file(files)
			value = self.format_value(data_input)
			response = self.scan_lookup(value)
			self.output_file(response, output, files=files)
			
			messagebox.showinfo(message="BulkVT lookup is complete!")
			
			
if __name__ == "__main__":
	
	root = Tk()
	root.title("BulkVT Lookup")
	App(root)
	root.mainloop()
