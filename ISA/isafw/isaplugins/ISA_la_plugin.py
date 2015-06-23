# License alazyser plugin
# Functions is based on similar scripts from Clear linux project

import subprocess
import os
import re

LicenseChecker = None

flicenses = "/home/elena/Python/image_security_analyser-isa/ISA/plugins/configs/la/licenses"
fapproved_non_osi = "/home/elena/Python/image_security_analyser-isa/ISA/plugins/configs/la/approved-non-osi"
fexceptions = "/home/elena/Python/image_security_analyser-isa/ISA/plugins/configs/la/exceptions"

class ISA_LicenseChecker():    
    initialized = False

    def __init__(self, proxy):
        self.proxy = proxy
        # check that rpm is installed (supporting only rpm packages for now)
        rc = subprocess.call(["which", "rpm"])        
        if rc == 0:
                self.initialized = True
                print("Plugin ISA_LicenseChecker initialized!")
        else:
            print("rpm tool is missing!")

    def process_package_source(self, ISA_pkg, report_path):
        # print ISA_pkg.name
        # print ISA_pkg.path_to_sources
        if (self.initialized == True):
            if (ISA_pkg.name and ISA_pkg.path_to_sources):
                if (not ISA_pkg.licenses):
                    # need to determine the license itself first
                    if ( not ISA_pkg.source_files):
                        # need to build list of source files
                        ISA_pkg.source_files = self.find_files(ISA_pkg.path_to_sources)
                        # print ISA_pkg.source_files
                    for i in ISA_pkg.source_files:
                        if (i.endswith(".spec")): # supporting rpm only for now
                            args = ("rpm", "-q", "--queryformat","%{LICENSE} ", "--specfile", i)
                            try:
                                popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                                popen.wait()
                                ISA_pkg.licenses = popen.stdout.read().split()
                            except:
                                print ("Error in executing rpm query: ", sys.exc_info())
                                print "Not able to process package: ", ISA_pkg.name
                                return 
                #bb.warn('Package licenses: %s' % ISA_pkg.licenses)
                for l in ISA_pkg.licenses:                                               
                    if (not self.check_license(l, flicenses) 
                    and not self.check_license(l, fapproved_non_osi)
                    and not self.check_exceptions(ISA_pkg.name, l, fexceptions)):
                        # log the package as not following correct license
                        report = report_path + "/license_report"
                        with open(report, 'a') as freport:
                            freport.write(ISA_pkg.name + ": " + l + "\n")
            else:
                print("Mandatory arguments such as pkg name and path to sources are not provided!")
                print("Not performing the call.")
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

def init(proxy):
    global LicenseChecker 
    LicenseChecker = ISA_LicenseChecker(proxy)
def getPluginName():
    return "license_check"
def process_package_source(ISA_pkg, report_path):
    global LicenseChecker 
    return LicenseChecker.process_package_source(ISA_pkg, report_path)

#====================================================#
