#
# ISA_cve_plugin.py -  CVE checker plugin, part of ISA FW
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
import re

CVEChecker = None

class ISA_CVEChecker:    
    initialized = False
    def __init__(self, proxy):
        self.proxy = proxy
        # check that cve-check-tool is installed
        rc = subprocess.call(["which", "cve-check-tool"])
        if rc == 0:
            self.initialized = True
            print("Plugin ISA_CVEChecker initialized!")
        else:
            print("cve-check-tool is missing!")
            print("Please install it from https://github.com/ikeydoherty/cve-check-tool.")

    def process_package_list(self, package_list):
        # print("package_list: ", package_list)
        if (self.initialized == True):
            args = ("cve-check-tool", "-N", "-c", "-a", package_list)
            try:
                popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                popen.wait()
                output = popen.stdout.read()
            except:
                print("Error in executing cve-check-tool: ", sys.exc_info())
                output = "Error in executing cve-check-tool"
            else:
                with open(report, 'w') as freport:
                    freport.write(output)
                #print("output: ", output)
        else:
            print("Plugin hasn't initialized! Not performing the call.")

    def process_package_source(self, ISA_pkg, report_path):
        if (self.initialized == True):
            if (ISA_pkg.name and ISA_pkg.version and ISA_pkg.patch_files):    
                # need to compose faux format file for cve-check-tool
                ffauxfile = report_path + "/fauxfile"
                cve_patch_info = self.process_patch_list(ISA_pkg.patch_files)
                with open(ffauxfile, 'w') as fauxfile:
                    fauxfile.write(ISA_pkg.name + "," + ISA_pkg.version + "," + cve_patch_info + ",")
                args = self.proxy + " cve-check-tool -N -c -a -t faux " + ffauxfile
                try:
                    popen = subprocess.Popen(args, shell=True, stdout=subprocess.PIPE)
                    popen.wait()
                    output = popen.stdout.read()
                except:
                    print("Error in executing cve-check-tool: ", sys.exc_info())
                    output = "Error in executing cve-check-tool"
                else:
                    report = report_path + "/cve-report"
                    with open(report, 'a') as freport:
                        freport.write(output)
            else:
                print("Mandatory arguments such as pkg name, version and list of patches are not provided!")
                print("Not performing the call.")
        else:
            print("Plugin hasn't initialized! Not performing the call.")

    def process_patch_list(self, patch_files):
        patch_info = ""
        for patch in patch_files:
            patch1 = patch.partition("cve")
            if (patch1[0] == patch):
                # no cve substring, try CVE
                patch1 = patch.partition("CVE")
                if (patch1[0] == patch):
                    continue
            patchstripped = patch1[2].split('-')
            patch_info += " CVE-"+ patchstripped[1]+"-"+re.findall('\d+', patchstripped[2])[0]
        return patch_info

                
    

#======== supported callbacks from ISA =============#

def init(proxy):
    global CVEChecker 
    CVEChecker = ISA_CVEChecker(proxy)
def getPluginName():
    return "cve-check"
def process_package_list(package_list):
    global CVEChecker 
    return CVEChecker.process_package_list(package_list)
def process_package_source(ISA_pkg, report_path):
    global CVEChecker 
    return CVEChecker.process_package_source(ISA_pkg, report_path)

#====================================================#

