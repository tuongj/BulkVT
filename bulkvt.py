#!/usr/bin/python
#The MIT License (MIT)
#Copyright (c) 2016 Jimmy Tuong (tuongj@gmail.com)
#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

__author__ = 'Jimmy Tuong'
__license__ = 'MIT'
__version__ = '1.0'
__email__ = 'tuongj@gmail.com'

import urllib.request, urllib.parse
import csv, json, hashlib, os
from tkinter import *
from tkinter.ttk import *
from tkinter import filedialog, messagebox


class VirusTotal():
	def __init__(self):
		self.reportfile = 'https://www.virustotal.com/vtapi/v2/file/report'
		self.proxy = {'http':'http://www.example.com:80'}	# Insert proxy here (Optional)
	
	
	def read_apikey(self):
		filepath = os.path.dirname(os.path.realpath(__file__)) + '\\bulkvt_key.txt'
		
		with open(filepath, 'r') as file:
			for line in file.readlines():
				self.apikey = line
				
				
	def has_apikey(self):
		try:
			if len(self.apikey) >= 64:
				return True
		except Exception:
			return False
	
	
	def format_list(self, filepath):
		parameters = {}
		list = []
		
		with open(filepath, 'r') as file:
			
			if filepath.endswith('.csv'):
				reader = csv.reader(file)
				
				for row in reader:
					x = '\n'.join(row)
					
					for line in x.splitlines():
						if self.is_hash(line):
							list.append(line)
						
			elif filepath.endswith('.txt') or filepath.endswith('.log'):
				for line in file.readlines():
					list.append(line.strip())
				
		values = ', '.join(str(i) for i in list)
		
		parameters['resource'] = values
		parameters['apikey'] = self.apikey
				
		return parameters
	
	
	def format_value(self, input):
		parameters = {}
		
		if self.is_hash(input) == False:
			values = ', '.join(str(i) for i in input)
		else:
			values = input
		
		parameters['resource'] = values
		parameters['apikey'] = self.apikey
				
		return parameters
	
	
	def get_file_listing(self, dir):
		items = []
		
		for root, dirs, files in os.walk(dir, topdown=True, onerror=None, followlinks=False):
			for file in files:
				file_path = os.path.abspath(os.path.join(root, file))
				items.append(file_path)
		
		return items
	
	
	def scan_lookup(self, parameters):
		data = urllib.parse.urlencode(parameters)
		data = data.encode('ascii')
		
		proxy_handler = urllib.request.ProxyHandler(self.proxy)
		opener = urllib.request.build_opener(proxy_handler)
		urllib.request.install_opener(opener)

		request = urllib.request.urlopen(self.reportfile, data)
		response = request.read().decode('utf-8')
		
		report = json.loads(response)
		
		return report
	
	
	def output_file(self, response, output, files=None):
		header = ['MD5', 'SHA1', 'SHA256', 'Positive', 'Total', 'Scan Date', 'Reference']
		values = ['md5','sha1', 'sha256', 'positives','total','scan_date', 'permalink']
		list = []
				
		if files is not None:
			for idx, item in enumerate(response):
				item['file path'] = files[idx]
			header.insert(0,'File')
			values.insert(0,'file path')
		
		with open(output, 'w', newline='\n') as f:
						
			if output.endswith('.csv'):
				csvfile = csv.writer(f)
				csvfile.writerow(header)
				
				for item in response:
					
					if item['response_code'] == 1:
						for value in values:
							list.append(item[value])
						
						csvfile.writerow(list)

						list[:] = []
					else:
						error = ' '.join([item['resource'], 'not found. The file you are looking for is not in the database.'])
						csvfile.writerow([error])
		
			elif output.endswith('.txt') or output.endswith('.log'):
				f.write(','.join(header))
				f.write('\n')
				
				for item in response:
					
					if item['response_code'] == 1:
						for value in values:
							list.append(item[value])
						
						joinitem = ','.join(str(i) for i in list)
							
						f.write(joinitem)
						f.write('\n')
						
						list[:] = []
		
					else:
						error = ' '.join([item['resource'], 'not found. The file you are looking for is not in the database.\n'])
						f.write(error)
	
	
	def output_result(self, file, item):
		if self.is_hash(file) == False:
			file = file[0]
		
		if item['response_code'] == 1:
			LIST = [item['md5'],
					item['sha1'],
					item['sha256'],
					item['positives'],
					item['total'],
					item['scan_date'],
					item['permalink']]
			result = 'MD5: {0}\nSHA1: {1}\nSHA246: {2}\nPositive: {3}\nTotal: {4}\nScan Date: {5}\nReference:\n{6}'.format(*LIST)
		elif item['response_code'] == 0:
			result = '{0} not found. The file you are looking for is not in the database.'.format(file)
		
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
		
		for file in items:
			with open(file, 'rb') as f:
				buffer = f.read(BLOCKSIZE)
				while len(buffer) > 0:
					md5.update(buffer)
					buffer = f.read(BLOCKSIZE)
		
			hash.append("{0}".format(md5.hexdigest()))
			if isinstance(files, list):
				md5 = hashlib.md5()
				
		return hash
	
	
	def is_hash(self, item):
		num = [32, 40, 64]
		
		if len(item) in num:
			match_obj = re.match('([a-fA-F0-9])', item)
			if match_obj:
				return True
		
		return False
	
		
class App(VirusTotal):
	def __init__(self, master):
		VirusTotal.__init__(self)
		
		self.master = master
		self.frame = Frame(master)
		
		for r in range(1,4):
			self.frame.rowconfigure(r, weight=1)
		for c in range(1,3):
			self.frame.columnconfigure(c, weight=1)
		
		self.create_widgets(self.frame)
		
		self.frame.pack(fill=X, expand=YES)
	
	
	def create_widgets(self, frame):
		self.setpadx = 5
		self.setpady = 5
		self.submit_type = IntVar()
		self.MODES = [('Single Hash/File', 1),
					('Bulk Hash', 2),
					('Directory', 3)]
		self.FILETYPES = [('All files', '.*'),
				('Batch files', '.bat'),
				('Dynamic Link Library files', '.dll'),
				('JavaScript files', '.js'),
				('MS-DOS program', '.com'),
				('Executable files', '.exe'),
				('Screen saver files', '.scr'),
				('VBScript files', '.vb;*.vbs')]
		self.FILETYPES2 = [('All files', '.csv;*.log;*.txt'),
						('CSV files', '.csv'),
						('Log files','.log'),
						('Text files', '.txt')]
		self.FILETYPES3 = [('CSV files', '.csv'),
						('Log files','.log'),
						('Text files', '.txt')]
		
		menu = Menu(frame)
		self.master.config(menu=menu)
		
		menu_file = Menu(menu, tearoff=0)
		menu_file.add_command(label='API Key', command=self.prompt_apikey)
		menu_file.add_separator()
		menu_file.add_command(label='Exit', command=self.client_exit)
		menu.add_cascade(menu=menu_file, label='File')
		
		
		self.submit_label = Label(frame, text='Submission Type:')
		self.submit_label.grid(row=0, column=0, padx=self.setpadx, sticky='E')
				
		self.submit_type.set(1)
		for idx, (text, value) in enumerate(self.MODES, start=1):
			self.radiotype = Radiobutton(frame, text=text, variable=self.submit_type, value=value, command=lambda: self.dynamic_widgets(frame))
			self.radiotype.grid(row=0, column=idx, padx=self.setpadx, sticky='NSEW')
		self.radiotype.invoke()
		
		
		self.input = Label(frame, text='Source:')
		self.input.grid(row=1, column=0, sticky='E')
		
		self.input_entry = Entry(frame, width=50)
		self.input_entry.grid(row=1, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky='NSWE')
		
		self.input_button = Button(frame, text='...', command=lambda: self.input_action())
		self.input_button.grid(row=1, column=6, sticky='E')
				
		Separator(frame, orient=HORIZONTAL).grid(row=2, columnspan=8, pady=self.setpady, sticky='WE')
	
		self.submit_button = Button(frame, text='Submit', command=lambda: self.submit_action())
		self.submit_button.grid(row=4, column=1, columnspan=2, pady=self.setpady, sticky='NSWE')
	
	
	def dynamic_widgets(self, frame):
		self.selected_type = self.submit_type.get()
		
		try:
			self.output.grid_forget()
			self.output_entry.grid_forget()
			self.output_button.grid_forget()
			self.input_entry.delete(0, END)
		except Exception:
			pass
		
		if self.selected_type == 1:
			self.input_entry.insert(0, 'Enter hash or select a file...')
			self.input_entry.bind('<Button-1>', self.on_entry_click)
		
			self.output = Label(frame, text='Result:')
			self.output.grid(row=3, column=0, sticky='E')
			
			self.output_entry = Text(frame, width=50, height=10)
			self.output_entry.grid(row=3, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky='NSWE')
		
		if self.selected_type == 2 or self.selected_type == 3:
			self.output = Label(frame, text='Destination:')
			self.output.grid(row=3, column=0, sticky='E')
		
			self.output_entry = Entry(frame, width=50)
			self.output_entry.grid(row=3, column=1, columnspan=5, padx=self.setpadx, pady=self.setpady, sticky='NSWE')
			
			self.output_button = Button(frame, text='...', command=lambda: self.output_action())
			self.output_button.grid(row=3, column=6, sticky='E')
	
	
	def prompt_apikey(self):
		top = Toplevel(self.frame)
		
		label = Label(top, text='Enter VirusTotal API Key:')
		label.grid(row=0, padx=self.setpadx, pady=self.setpady, sticky='NS')
		
		self.key_entry = Entry(top, width=70)
		self.key_entry.grid(row=1, padx=self.setpadx, pady=self.setpady, sticky='NSWE')
		
		button = Button(top, text='Submit', command=lambda: self.create_apikey(top))
		button.grid(row=2, padx=self.setpadx, pady=self.setpady, sticky='NS')
		
	
	def create_apikey(self, top):
		key = self.key_entry.get().replace(' ','')
		filepath = os.path.dirname(os.path.realpath(__file__)) + '\\bulkvt_key.txt'
		
		if len(key) < 64:
			messagebox.showerror(message='Your API key is invalid. Please insert a valid API key.')
		else:
			with open(filepath, 'w+') as file:
				file.write(key)
			messagebox.showinfo(message='Your API key has been saved in\n' + filepath)
		top.destroy()
	
	
	def client_exit(self):
		sys.exit()
	
	
	def on_entry_click(self, event):
		str = self.input_entry.get()
		
		if str == 'Enter hash or select a file...':
			self.input_entry.delete(0, END)
	
	
	def input_action(self):
		if self.selected_type == 1:
			dialog = filedialog.askopenfilename(defaultextension='.*', filetypes=self.FILETYPES)
		elif self.selected_type == 2:
			dialog = filedialog.askopenfilename(filetypes=self.FILETYPES2)
		elif self.selected_type == 3:
			dialog = filedialog.askdirectory()
		
		if self.selected_type != 0:
			self.input_entry.delete(0, END)
			self.input_entry.insert(END, dialog)
	
		
	def output_action(self):
		dialog = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=self.FILETYPES3)
		
		self.output_entry.delete(0, END)
		self.output_entry.insert(END, dialog)
	
	
	def submit_action(self):
		input = self.input_entry.get().strip()
		
		try:
			self.read_apikey()
			output = self.output_entry.get()
		except Exception:
			pass
		
		if not self.has_apikey():
			messagebox.showerror(message='You need an API key.\nClick on the menu File > API Key to insert your API Key.')
		#elif not self.output_entry.get():
			#messagebox.showinfo(message='You must select an output path!')
		#elif not self.input_entry.get():
			#messagebox.showinfo(message='You must select a source!')
		
		elif self.selected_type == 1:
			try:
				if self.is_hash(input) == False:
					input = self.hash_file(input)
				
				value = self.format_value(input)
				response = self.scan_lookup(value)
				result = self.output_result(input, response)
			except Exception as e:
				result = e
			finally:
				self.output_entry.delete(1.0, END)
				self.output_entry.insert(END, result)
				
		elif self.selected_type == 2:
			scan = self.format_list(input)
			response = self.scan_lookup(scan)
			self.output_file(response, output)
			
			messagebox.showinfo(message='BulkVT lookup is complete!')
			
		elif self.selected_type == 3:
			files = self.get_file_listing(input)
			input = self.hash_file(files)
			value = self.format_value(input)
			response = self.scan_lookup(value)
			self.output_file(response, output, files)
			
			messagebox.showinfo(message='BulkVT lookup is complete!')
			
			
if __name__ == '__main__':
	
	root = Tk()
	root.title('BulkVT Lookup')
	App(root)
	root.mainloop()
