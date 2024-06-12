EBICS Java Client
=====

This library allows to interact with banks using the EBICS (Electronic Banking Internet Communication Standard)

You can use the `EbicsClient` as command line tool or use it from your Java application.

How to get started:

https://github.com/ebics-java/ebics-java-client/wiki/EBICS-Client-HowTo

You can build it directly from the source with maven or use the releases from [JitPack](https://jitpack.io/#ebics-java/ebics-java-client/).

Gradle:
```
allprojects {
  repositories {
    ...
    maven { url 'https://jitpack.io' }
  }
}

dependencies {
    implementation 'com.github.ebics-java:ebics-java-client:master-SNAPSHOT'
}
```
Maven
```
<repositories>
	<repository>
	    <id>jitpack.io</id>
	    <url>https://jitpack.io</url>
	</repository>
</repositories>

<dependency>
    <groupId>com.github.ebics-java</groupId>
    <artifactId>ebics-java-client</artifactId>
    <version>master-SNAPSHOT</version>
</dependency>
```
 

This project is based on https://sourceforge.net/p/ebics/

Main differences with this fork:

- Support for French, German and Swiss banks
- Command line client to do the setup, initialization and to download files from the bank
- Use of maven for compilation instead of ant + Makefile + .sh scripts

### Log
- XMLBeans doesn't keep the DOM pretty-printed. The pretty-print parameter is just used before writing.
  This effectively breaks the signature stuff, which is why upstream had to use like 3 different XML
  frameworks and would read and write everything 5 times.
- The same is true for namespace prefixes. In the DOM, namespace prefixes are assigned arbitrarily,
  even when I try to configure them on creation. Only when I write everything out is my configuration
  used.
- This means I cannot do what seems to be the idea of XML Security, which is construct my document
  and then let the XML Security library sign parts of it in the DOM. When I write everything out,
  XMLBeans will think it can rewrite stuff and my signature will be invalid.
- This means that while XML Security is somewhat brittle by design, XMLBeans is an odd choice
  as a tool for this particular project.
- When I try to update XMLBeans to the latest version, I find that it is half-retired and only
  used to read MS Office files these days.
- When I still try to use the latest version, I find that it doesn't read the official EBICS schema
  files because they contain "0" as a value for maxOccurs which is both factually wrong
  and a syntax error.
- When I correct those errors in my local version of the schema, XMLBeans still won't compile them
  but now it won't say why.
- Backtrack to original version of XMLBeans.
- When I use XPath on a namespace-aware DOM, and select the element with authenticate=true, 
  I of course get a DOM node that has a namespace tag, and that is the element that 
  the canonicalizer then sees. So while the canonicalizer doesn't touch namespace tags,
  the canonicalization INCLUDING the XPath selection DOES touch namespace tags. I am not sure
  if that is intended and such things will verify correctly.
