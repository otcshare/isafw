#ISA CVE checker plugin
import subprocess
import os

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
        # print package_list
        if (self.initialized == True):
            args = ("cve-check-tool", "-N", "-c", "-a", package_list)
            try:
                popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                popen.wait()
                output = popen.stdout.read()
            except:
                print ("Error in executing cve-check-tool: ", sys.exc_info())
                output = "Error in executing cve-check-tool"
            else:
                with open(report, 'w') as freport:
                    freport.write(output)
                #print output
        else:
            print("Plugin hasn't initialized! Not performing the call.")

    def process_package_source(self, ISA_pkg, report_path):
        if (self.initialized == True):
            if (ISA_pkg.name and ISA_pkg.path_to_sources):    
                # supporting rpm for now
                args = self.proxy + " cve-check-tool -N -c -a -t rpm -s \"" + ISA_pkg.path_to_sources+"\" \""+ISA_pkg.path_to_spec+"\""
                #print args
                try:
                    popen = subprocess.Popen(args, shell=True, stdout=subprocess.PIPE)
                    popen.wait()
                    output = popen.stdout.read()
                except:
                    print ("Error in executing cve-check-tool: ", sys.exc_info())
                    output = "Error in executing cve-check-tool"
                else:
                    report = report_path + "/cve-report"
                    print output
                    with open(report, 'a') as freport:
                        freport.write(output)
                    print output
            else:
                print("Mandatory arguments such as pkg name and path to sources are not provided!")
                print("Not performing the call.")
        else:
            print("Plugin hasn't initialized! Not performing the call.")



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

