#ISA CVE checker plugin
import subprocess

CVEChecker = None
report = "./cve_report"

class ISA_CVEChecker:    
    initialized = False
    def __init__(self):
        # check that cve-check-tool is installed
        rc = subprocess.call(["which", "cve-check-tool"])
        if rc == 0:
            self.initialized = True
            print("Plugin ISA_CVEChecker initialized!")
        else:
            print("cve-check-tool is missing!")
            print("Please install it from https://github.com/ikeydoherty/cve-check-tool.")
    def process_package_list(self, package_list):
        print package_list
        if (self.initialized == True):
            args = ("cve-check-tool", "-N", "-c", "-a", package_list)
            popen = subprocess.Popen(args, stdout=subprocess.PIPE)
            popen.wait()
            output = popen.stdout.read()
            f = open(report,'w')
            f.write(output)
            f.close() 
            #print output
        else:
            print("Plugin hasn't initialized! Not performing the call.")


#======== supported callbacks from ISA =============#

def init():
    global CVEChecker 
    CVEChecker = ISA_CVEChecker()
def getPluginName():
    return "cve-check"
def process_package_list(package_list):
    global CVEChecker 
    return CVEChecker.process_package_list(package_list)

#====================================================#

