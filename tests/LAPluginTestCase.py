#
# LAPluginTestCase.py -  Test cases for License Checker plugin, part of ISA FW
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
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE

import unittest
import sys
sys.path.append("../isafw") 
import isafw
import shutil
import os


reportdir = "./la_plugin/output"

class TestLAPlugin(unittest.TestCase):

    def setUp(self):
        # cleaning up the report dir and creating it if needed
        if os.path.exists(os.path.dirname(reportdir+"/internal/test")):
            shutil.rmtree(reportdir)
        os.makedirs(os.path.dirname(reportdir+"/internal/test"))
        # fetching proxy info
        proxy = ""
        if "http_proxy" in os.environ:
            proxy = os.environ['http_proxy']
        if "https_proxy" in os.environ:
            proxy = os.environ['https_proxy']
        # creating ISA FW class
        self.imageSecurityAnalyser = isafw.ISA(proxy, reportdir)

    def test_package_with_licenses_OK(self):
        pkg = isafw.ISA_package()
        pkg.name = "bash"
        pkg.version = "4.3"
	pkg.licenses = ["Apache-1.1"]
        self.imageSecurityAnalyser.process_package(pkg)
        badLicExist = os.path.isfile (reportdir + "/license_report")	
	# if no bad licenses exist no report is created        
	self.assertFalse(badLicExist)

    def test_package_with_licenses_NotOK(self):
        pkg = isafw.ISA_package()
        pkg.name = "bash"
        pkg.version = "4.3"
	pkg.licenses = ["BadLicense-1.1"]
	self.imageSecurityAnalyser.process_package(pkg)		
	with open(reportdir + "/license_report", 'r') as freport:
            output = freport.readline()
	    print(output)
	# if bad licenses exist a report listing them is created
        self.assertEqual(output, 
                        "bash: BadLicense-1.1\n",
                        'Output does not match')  


if __name__ == '__main__':
    unittest.main()

