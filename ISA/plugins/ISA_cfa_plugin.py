#Compile flag alazyser plugin
import subprocess
import os

CFChecker = None

class ISA_CFChecker():    
    initialized = False
    def __init__(self):
        # check that cve-check-tool is installed
        rc = subprocess.call(["which", "checksec.sh"])
        if rc == 0:
            self.initialized = True
            print("Plugin ISA_CFChecker initialized!")
        else:
            print("checksec tool is missing!")
            print("Please install it from http://www.trapkit.de/tools/checksec.html")
    def process_fsroot(self, fsroot_path):
        print fsroot_path
        if (self.initialized == True):
            self.files = self.find_files(fsroot_path)
            print self.files
            for i in self.files:
                if os.path.isfile(i):
                    # getting file type
                    cmd = ['file', '--mime-type', i]
                    result = subprocess.check_output(cmd).decode("utf-8")
                    type = result.split()[-1]
                    # looking for links
                    if type.find("symlink") != -1:
                        real_file = os.path.realpath(i)
                        cmd = ['file', '--mime-type', real_file]
                        result = subprocess.check_output(cmd).decode("utf-8")
                        type = result.split()[-1]
                    # building the name_field
                    if i == real_file:
                        name_field = i
                    else:
                        name_field = i+" -> "+real_file
                    # getting file size
                    size = os.path.getsize(real_file)
                    # checking file permissions
                    mode = stat.S_IMODE(os.stat(real_file).st_mode)
                    # checking security flags if applies
                    if type.find("application") != -1:
                        if type.find("octet-stream") != -1:
                            sec_field = "File is octect-stream, can not be analyzed with checksec.sh"
                        elif type.find("dosexec") != -1:
                            sec_field = "File MS Windows binary"
                        elif type.find("archive") != -1:
                            sec_field = "File is an archive"
                        elif type.find("xml") != -1:
                            sec_field = "File is xml"
                        elif type.find("gzip") != -1:
                            sec_field = "File is gzip"
                        elif type.find("postscript") != -1:
                            sec_field = "File is postscript"
                        elif type.find("pdf") != -1:
                            sec_field = "File is pdf"
                        else:
                            sec_field = get_security_flags(real_file)
                    else:
                        sec_field = "File is not binary"
                    # checking flags criteria
                    print sec_field

        else:
            print("Plugin hasn't initialized! Not performing the call.")

    def find_files(self, init_path):
        list_of_files = []
        for (dirpath, dirnames, filenames) in os.walk(init_path):
            for f in filenames:
                list_of_files.append(str(dirpath+"/"+f)[(len(init_path)-1):])
        return list_of_files

    def get_security_flags(self, file_name):
        SF = {
	        'No RELRO'        : 0,
	        'Full RELRO'      : 2,
	        'Partial RELRO'   : 1,
	        'Canary found'    : 1,
	        'No canary found' : 0,
	        'NX disabled'     : 0,
	        'NX enabled'      : 1,
	        'No PIE'          : 0,
	        'PIE enabled'     : 3,
	        'DSO'             : 2,
	        'RPATH'           : 0,
	        'Not an ELF file' : 1,
	        'No RPATH'        : 1,
	        'RUNPATH'         : 0,
	        'No RUNPATH'      : 1
        }
        cmd = ['checksec.sh', '--file', file_name]
        result = subprocess.check_output(cmd).decode("utf-8").split('\n')[1]
        ansi_escape = compile(r'\x1b[^m]*m')
        text = ansi_escape.sub('', result)
        text2 = sub(r'\ \ \ *', ',', text).split(',')[:-1]
        text = []
        for t2 in text2:
	        text.append((t2, SF[t2]))
        return text


#======== supported callbacks from ISA =============#

def init():
    global CFChecker 
    CFChecker = ISA_CFChecker()
def getPluginName():
    return "compile_flag_check"
def process_fsroot(fsroot_path):
    global CFChecker 
    return CFChecker.process_fsroot(fsroot_path)

#====================================================#

