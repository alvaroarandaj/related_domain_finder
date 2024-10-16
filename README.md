# Related Domain Finder
A tool to find domains related to an input domain


## Prerequisites

* Python:

The first step will be to have Python installed on the local machine.

To do this, we recommend going to the official website and downloading it from there:

https://www.python.org/downloads/

Our tool is developed under the version 3.12 of Python.

* Google API Key:

If you want to squeeze all the tool potential, you will have to generate a Google API key so that the tool can work with its full potential. You can find this at the following link: 

https://support.google.com/googleapi/answer/6158862?hl=en

Once you have it, you will have to configure it in the main.py file by replacing the two necessary parameters with the ones that say 'xxx' and 'yyy'


## How to use

Once you have everything installed and correctly configured, you will only have to run the 'Related domain finder.bat' file.

The program has two modes:
* <b>[0] Debug:</b> This is the debugging mode which shows step by step what it does during each of the domain analyzes that the program does. Only recommended if you want to see any specific details of any of the domains.
* <b>[1] Normal:</b> This is the default mode of the program that keeps its output clean.

You just have to select one of them, the program will ask you to enter the URL you want to analyze and all you have to do is wait for the results for around 10-15 minutes.


## Flow

<p align="left">
<img  src="Diagram_English.png?raw=true" width="70%"/>
</p>

<b>Program flow:</b>
1. The user enters a URL.
2. Searches are carried out using Google, NS Lookup and Wayback Machine.
3. The results are analyzed using DNS, WHOIS, TLS Certificates and CA.
4. It is determined if the domains are related, or partially, with the initial URL.
5. The results are shown grouping the domains according to their relationship.


## Results

3 Kind of results are shown:

* <b>Subdomains:</b> They are related domains but are part of the same global URL. 
* <b>Related domains:</b> They are domains that guarantee that they have a reliable relationship with the domain given in the entry.
* <b>Partial related domains:</b> They are domains that only have some indication of being related to the input domain. 
