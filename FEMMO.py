#!/usr/bin/env python
#
# Name: Federation Metadata Manager for ADFS (FEMMA)
# Version: 0.1
# Author: Cristian Mezzetti cristian.mezzetti@unibo.it
# Edited By: Dave Martinez
# Home-page: http://sourceforge.net/projects/femma
# License: GNU GPL v2
# Description: This script parses a (Shibboleth) federation 
#              metadata XML content and creates a pool of 
#              metadata files and a powershell script in order
#              to automatically configure and update an Active
#              Directory Federation Services STS (Security Token Service).
#l

# Copyright (C) 2010  Cristian Mezzetti
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.

from lxml import etree
from lxml import objectify
import urllib2, os, sys, getopt, string, ConfigParser, re
from string import Template
import json

#### Adapt to your needs
spEntityID = "fedletsp"
myClaimType = 'http://unibo/idem'
fedNamePrefix = "IDEM"
######################

settingsFile = "settings.cfg"
xmlDir = os.getcwd() + os.sep + "entities-temp"
rulesetDir = os.getcwd() + os.sep + "ruleset-temp"
templateDir = os.getcwd() + os.sep + "templates"
extendedTemplate = templateDir + os.sep + "idp-extended.tpl"
cotTemplate = templateDir + os.sep + "fedlet.cot.tpl"
jsonTemplate=templateDir+os.sep + "eds.json.tpl"
#circle of trust id's
cot=[]
def tearUp():
   """ #@IndentOk
   Initializes temp directories and checks for templates
   """
   print("Starting")
   if os.path.exists(templateDir):
      if not (os.path.exists(xmlDir) and os.path.isdir(xmlDir)):
          os.mkdir(xmlDir)
 #     if not (os.path.exists(rulesetDir) and os.path.isdir(rulesetDir)):
 #         os.mkdir(rulesetDir)
   else:
      print "ERROR: Template dir " + templateDir + " not found."
      sys.exit(1)



def entityToIgnore(entityID):
   """
   Checks if the provided entityID of the Identity Provider is blacklisted
   To blacklist an entity ID create a settings file with similar syntax:
   [ExcludeEntityID]
   entity1 = "https://my.example.com/service"
   entity2 = "https://anotherexample.net/service2"
   """
   if os.path.exists(settingsFile):
      config = ConfigParser.ConfigParser()
      config.read(settingsFile)
      toIgnore = config.items('ExcludeEntityID')

      if entityID in [x[1] for x in toIgnore]:
         return True
      else:
         return False

def stripRolloverKeys(entity):
   """
   If the entity metadata contains keys for safe-rollover, strips the Standby key because ADFS can't handle it
   """
   toRemove = []
   for i in entity.iterdescendants('{http://www.w3.org/2000/09/xmldsig#}KeyName'):
      if i.text == "Standby":
         toRemove.append(i.getparent().getparent())

   for j in toRemove:
      parent = j.getparent()
      parent.remove(j)
      print "WARNING: removed KeyName element used for safe-rollover (ADFS can't handle it)"

   return entity

def createjsonentry(entity):
    
   
    
    organization = entity.find('{urn:oasis:names:tc:SAML:2.0:metadata}Organization')
    organizationNameEntity=organization.find('{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationDisplayName')
    lang=organizationNameEntity.attrib['{http://www.w3.org/XML/1998/namespace}lang']
    for element in organizationNameEntity.iter():
        #print("%s - %s" % (element.tag, element.text))
       

        displayname={"value":element.text,"lang":lang}
        
        jsonObject={"entityID":entity.attrib['entityID'],"DisplayNames":[displayname]}
        return jsonObject
    #print tree
    
    
    
                  #organization= entity.find('{urn:oasis:names:tc:SAML:2.0:metadata}Organization')
                  #organizationNameEntity=organization.find('{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationDisplayName')
                  #organizationName=organizationNameEntity.text
                  #language=organizationName.attrib['{http://www.w3.org/XML/1998/namespace}lang']
                  #create json object and write to the file
                  



def createExtendedIDP(entity,i):
              
              print "Generating extended metadata for the new identity provider : " + entity.attrib['entityID']
              
              extTemplateFile=open(extendedTemplate, 'r')
              extendedIdpTemplate = Template(extTemplateFile.read())
              extTemplateFile.close()
              extFileName = xmlDir + os.sep +"idp"+str(i)+"-extended.xml"
              extFile = open(extFileName, 'w') 
              extFile.write(extendedIdpTemplate.substitute(entityid=entity.attrib['entityID']))      
              extFile.close()

             
def metadataExtraction(mdUrl, xmlDir):
   """
   Creates a metadata file for each entityID in Federation EntitiesDescriptor
   """
   try:
      pshScript = ""
      

      md = urllib2.urlopen(mdUrl)
      mdString = md.read()
      # use CRLF instead of LF
      mdString = re.sub("\r?\n", "\r\n", mdString)
      fedMetadata = etree.fromstring(mdString)
      i=0
      jsonMetadata=[]
      # for EntityDescriptor extracts IDP and write a single metadata file
      for entity in fedMetadata.findall('{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'):
         idpDescriptor = entity.find('{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor')
         if (idpDescriptor is not None):
            attribute = idpDescriptor.get('protocolSupportEnumeration')
            # verifies that the IDP supports SAML2
            if (string.find(attribute, 'urn:oasis:names:tc:SAML:2.0:protocol') != -1):
               if not entityToIgnore(entity.attrib['entityID']):
                  # creates a metadata file with only one EntityDescriptor for ADFS
                  #entity = stripRolloverKeys(entity)
                  #entities = etree.fromstring(mdString)
                  #entities.clear()
                  #entities.insert(0, entity)
                  #fname = entity.attrib['entityID'].replace('/', '_').replace('.', '_').replace(':', '_')
                  #fname = "".join([x for x in fname if x.isalpha() or x.isdigit() or x == '-' or x == '_'])
                  # create json file
                  i+=1
                  jsonObject=createjsonentry(entity)
                  jsonMetadata.append(jsonObject)
                  fname="idp"+str(i)+".xml"
                  print "Generating XML metadata of " + entity.attrib['entityID'] + " Identity Provider"
                  entityFileName = xmlDir + os.sep + fname
                  entityFile = open(entityFileName, "w")
                  entityFile.write(etree.tostring(entity))
                  entityFile.close()
                  createExtendedIDP(entity,i)
                  cot.append(entity.attrib['entityID'])
      #print to cod
      
      cotT = Template(open(cotTemplate).read())
      cotString=''.join([`num`+',' for num in cot])
      print cotString
      jsonfile=open(xmlDir + os.sep +'idp.json',"w")
      json.dump(jsonMetadata,jsonfile)
      jsonfile.close()
      #write to file
      cotFile=open(xmlDir + os.sep +'fedlet.cot',"w")
      cotFile.write(cotT.substitute(providers=cotString))
      cotFile.close()
         
   except Exception, e:
      print(e)
   return

def usage(ret=0):
   print "-h, --help"
   print "-t, --test"
   print "-m, --metadata:   URL of federation metadata"
   print "-x, --xmlsec:     path to xmlsec binary for signature verification"
   sys.exit(ret)

def main():

   try:
      opts, args = getopt.getopt(sys.argv[1:], "htm:x:", ["help", "test", "metadata=", "xmlsec="])

   except getopt.GetoptError, err:
      print str(err)
      usage(2)

   mdUrl = ""
   if opts.__len__() != 0:
      for o, a in opts:
         if o in ("-x", "--xmlsec"):
            xmlsecbin = a
         elif o in ("-m", "--metadata"):
            mdUrl = a
         else:
            usage()
      metadataExtraction(mdUrl, xmlDir)
   else:
      usage()

if __name__ == "__main__":
   tearUp()
   main()
