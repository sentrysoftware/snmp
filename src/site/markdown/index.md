# SNMP Java Client

The SNMP Java Client enables you to execute basic SNMP operations, including:

* Initializing the SNMP Client
* Establishing a secure connection to a remote server
* Running commands on the remote server
* Conducting file transfers between local and remote machines through SCP

# How to run the SNMP Client inside Java

Add SNMP in the list of dependencies in your [Maven pom.xml](pom.xml):

```
<dependencies>
	<!-- [...] -->
	<dependency>
		<groupId>org.sentrysoftware</groupId>
		<artifactId>snmp</artifactId>
		<version>${project.version}</version>
	</dependency>
</dependencies>
```

Invoke the SNMP Client:

```
public static void main(String[] args) throws Exception {

            final String hostname = "my-hostname";
            final int port = 161;
            final int version = SnmpClient.SNMP_v2c;
            final int[] retryIntervals = {500, 1000, 2000};
            final String community = "my-community";
            final String authType = null; //SnmpClient.SNMP_AUTH_MD5;
            final String authUsername = null; //"my-username";
            final String authPassword = null; //"my-auth-password";
            final String privacyType = null; //SnmpClient.SNMP_PRIVACY_AES;
            final String privacyPassword = null; //"my-privacy-password";
            final String contextName = null; //"my-context-name";
            final byte[] contextID = {};

            SnmpClient snmpClient = new SnmpClient(hostname, port, version, retryIntervals, community,
                    authType, authUsername, authPassword, privacyType, privacyPassword, contextName, contextID);

            String oid = "my-oid";
            String result = snmpClient.getNext(oid);
            System.out.println("SNMP GET Result: " + result);
    }
```
