# License alazyser plugin
# Functions is based on similar scripts from Clear linux project

import subprocess
import os
import re

LicenseChecker = None
report = "./license_report"
flicenses = "../ISA/plugins/configs/la/licenses"
fapproved_non_osi = "../ISA/plugins/configs/la/approved-non-osi"
fexceptions = "../ISA/plugins/configs/la/exceptions"

class ISA_LicenseChecker():    
    initialized = False

    def __init__(self):
        # check that rpm is installed (supporting only rpm packages for now)
        rc = subprocess.call(["which", "rpm"])
        if rc == 0:
            self.initialized = True
            freport = open(report,'w')
            freport.write("Packages that have license violations:\n")
            freport.close() 
            print("Plugin ISA_LicenseChecker initialized!")
        else:
            print("rpm tool is missing!")
    def process_package_source(self, ISA_pkg):
        print ISA_pkg.name
        print ISA_pkg.path_to_sources
        if (self.initialized == True):
            if (ISA_pkg.name and ISA_pkg.path_to_sources):
                if (not ISA_pkg.license):
                    # need to determine the license itself first
                    if ( not ISA_pkg.source_files):
                        # need to build list of source files
                        ISA_pkg.source_files = self.find_files(ISA_pkg.path_to_sources)
                        print ISA_pkg.source_files
                    for i in ISA_pkg.source_files:
                        if (i.endswith(".spec")):
                            args = ("rpm", "-q", "--queryformat","%{LICENSE} ", "--specfile", i)
                            popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                            popen.wait()
                            ISA_pkg.license = popen.stdout.read()
                            print ISA_pkg.license
                licenses = ISA_pkg.license.split()
                for l in licenses:                                               
                    if (not self.check_license(l, flicenses) 
                    and not self.check_license(l, fapproved_non_osi)
                    and not self.check_exceptions(ISA_pkg.name, l, fexceptions)):
                        #log the package as not following correct license
                        freport = open(report,'a')
                        freport.write(ISA_pkg.name + ": " + l + "\n")
                        freport.close()                               
                    
            else:
                print("Mandatory arguments such as pkg name and path to sources are not provided! Not performing the call.")               
        else:
            print("Plugin hasn't initialized! Not performing the call.")

    def find_files(self, init_path):
        list_of_files = []
        for (dirpath, dirnames, filenames) in os.walk(init_path):
            for f in filenames:
                list_of_files.append(str(dirpath+"/"+f)[:])
        return list_of_files

    def check_license(self, license, file_path):
            with open(file_path, 'r') as f:
                for line in f:
                    s = line.rstrip()
                    if s == license:
                        return True
            return False

    def check_exceptions(self, pkg_name, license, file_path):
            with open(file_path, 'r') as f:
                for line in f:
                    s = line.rstrip()
                    if s == pkg_name + " " + license:
                        return True
            return False


#======== supported callbacks from ISA =============#

def init():
    global LicenseChecker 
    LicenseChecker = ISA_LicenseChecker()
def getPluginName():
    return "license_check"
def process_package_source(ISA_pkg):
    global LicenseChecker 
    return LicenseChecker.process_package_source(ISA_pkg)

#====================================================#