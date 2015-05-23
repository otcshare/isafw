# main class of Image Security Analyser
import os
import sys
import imp
import plugins

class ImageSecurityAnalyser:
    def __init__(self):
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                register_plugin = plugin.init
            except AttributeError:
                print("Error in calling init() for plugin " + plugin.getPluginName())
            else:
                 # try to call it, without catching any errors
                 register_plugin()

    def process_package(self, package_path):
        #print package_path
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_package = plugin.process_package
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 rprocess_package(package_path)


    def process_packages(self, packages_path):
        #print packages_path
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_packages = plugin.process_packages
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 process_packages(packages_path)
    def process_package_list(self, package_list):
        #print package_list
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_package_list = plugin.process_package_list
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 process_package_list(package_list)

    def process_fsroot(self, fsroot_path):
        #print fsroot_path
        for name in plugins.__all__:
            plugin = getattr(plugins, name)
            try:
               # see if the plugin has a 'register' attribute
                process_fsroot = plugin.process_fsroot
            except AttributeError:
                pass
            else:
                 # try to call it, without catching any errors
                 process_fsroot(fsroot_path)




