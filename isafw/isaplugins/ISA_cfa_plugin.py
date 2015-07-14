#
# ISA_cfa_plugin.py -  Compile flag analyzer plugin, part of ISA FW
# Main functionality is based on build_comp script from Clear linux project
#
# Copyright (c) 2015, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of Intel Corporation nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import subprocess
import os
import stat
from re import compile
from re import sub

CFChecker = None
full_report = "/cfa_full_report_"
problems_report = "/cfa_problems_report_"
log = "/isafw_cfalog"

class ISA_CFChecker():    
    initialized = False
    no_relo = []
    no_canary = []
    no_pie = []
    no_nx = []

    def __init__(self, proxy, reportdir):
        self.proxy = proxy
        self.reportdir = reportdir
        # check that checksec is installed
        rc = subprocess.call(["which", "checksec.sh"])
        if rc == 0:
            self.initialized = True
            print("Plugin ISA_CFChecker initialized!")
            with open(reportdir + log, 'w') as flog:
                flog.write("Plugin ISA_CFChecker initialized!\n")
        else:
            print("checksec tool is missing!")
            print("Please install it from http://www.trapkit.de/tools/checksec.html")
            with open(reportdir + log, 'w') as flog:
                flog.write("checksec tool is missing!\n")
                flog.write("Please install it from http://www.trapkit.de/tools/checksec.html\n")

    def process_fsroot(self, fsroot_path, imagebasename):
        #print("fsroot_path: ", fsroot_path)
        if (self.initialized == True):
            with open(self.reportdir + full_report + imagebasename, 'w') as ffull_report:
                ffull_report.write("Security-relevant flags for executables for image: " + imagebasename + '\n')
                ffull_report.write("With rootfs location at " +  fsroot_path + "\n\n")
            self.files = self.find_files(fsroot_path)
            #print("self.files: ", self.files)
            for i in self.files:
                real_file = i
                if os.path.isfile(i):
                    # getting file type
                    cmd = ['file', '--mime-type', i]
                    try:
                        result = subprocess.check_output(cmd).decode("utf-8")
                    except:
                        print("Not able to decode mime type", sys.exc_info())
                        with open(reportdir + log, 'a') as flog:
                            flog.write("Not able to decode mime type" + sys.exc_info())
                        continue
                    type = result.split()[-1]
                    # looking for links
                    if type.find("symlink") != -1:
                        real_file = os.path.realpath(i)
                        cmd = ['file', '--mime-type', real_file]
                        try:
                            result = subprocess.check_output(cmd).decode("utf-8")
                        except:
                            print("Not able to decode mime type", sys.exc_info())
                            with open(reportdir + log, 'a') as flog:
                                flog.write("Not able to decode mime type" + sys.exc_info())
                            continue
                        type = result.split()[-1]
                    # building the name_field
                    if i == real_file:
                        name_field = i
                    else:
                        name_field = i+" -> "+ real_file
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
                            sec_field = self.get_security_flags(real_file)
                            with open(self.reportdir + full_report + imagebasename, 'a') as ffull_report:
                                ffull_report.write(real_file + ": ")
                                for s in sec_field:
                                    line = ' '.join(str(x) for x in s)
                                    ffull_report.write(line + ' ')
                                ffull_report.write('\n')
                            
                    else:
                        sec_field = "File is not binary"
            # write report
            with open(self.reportdir + problems_report + imagebasename, 'w') as fproblems_report:
                fproblems_report.write("Report for image: " + imagebasename + '\n')
                fproblems_report.write("With rootfs location at " +  fsroot_path + "\n\n")
                fproblems_report.write("Files with no RELO:\n")
                for item in self.no_relo:
                    fproblems_report.write(item + '\n')
                fproblems_report.write("\n\nFiles with no canary:\n")
                for item in self.no_canary:
                    fproblems_report.write(item + '\n')
                fproblems_report.write("\n\nFiles with no PIE:\n")
                for item in self.no_pie:
                    fproblems_report.write(item + '\n')
                fproblems_report.write("\n\nFiles with no NX:\m")
                for item in self.no_nx:
                    fproblems_report.write(item + '\n')
        else:
            print("Plugin hasn't initialized! Not performing the call.")
            with open(reportdir + log, 'a') as flog:
                flog.write("Plugin hasn't initialized! Not performing the call.\n")

    def find_files(self, init_path):
        list_of_files = []
        for (dirpath, dirnames, filenames) in os.walk(init_path):
            for f in filenames:
                list_of_files.append(str(dirpath+"/"+f)[:])
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
        try:
            result = subprocess.check_output(cmd).decode("utf-8").split('\n')[1]
        except:
            return "Not able to fetch flags"
        else:
            ansi_escape = compile(r'\x1b[^m]*m')
            text = ansi_escape.sub('', result)
            text2 = sub(r'\ \ \ *', ',', text).split(',')[:-1]
            text = []
            for t2 in text2:
                if t2 == "No RELRO":
                    self.no_relo.append(file_name[:])
                elif t2 == "No canary found" :
                    self.no_canary.append(file_name[:])
                elif t2 == "No PIE" :
                    self.no_pie.append(file_name[:])
                elif t2 == "NX disabled" :
                    self.no_nx.append(file_name[:])
                text.append((t2, SF[t2]))               
            return text

#======== supported callbacks from ISA =============#

def init(proxy, reportdir):
    global CFChecker 
    CFChecker = ISA_CFChecker(proxy, reportdir)
def getPluginName():
    return "compile_flag_check"
def process_fsroot(fsroot_path, imagebasename):
    global CFChecker 
    return CFChecker.process_fsroot(fsroot_path, imagebasename)

#====================================================#

