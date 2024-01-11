# SNMP Java Client

![GitHub release (with filter)](https://img.shields.io/github/v/release/sentrysoftware/snmp)
![Build](https://img.shields.io/github/actions/workflow/status/sentrysoftware/snmp/deploy.yml)
![GitHub top language](https://img.shields.io/github/languages/top/sentrysoftware/snmp)
![License](https://img.shields.io/github/license/sentrysoftware/snmp)

The SNMP Java client enables you to run SNMP operations, including:

- SNMP Client initialization
- Execution of single requests (`Get` and `GetNext`), as well as multiple request functionalities (`Walk` and `Table`)
- Request execution on remote devices, supporting SNMP v1, v2c, or v3 implementations

See [Project Documentation](https://sentrysoftware.org/snmp/) and the [Javadoc](https://sentrysoftware.org/snmp/apidocs/) for more information on how to use this library in your code.

## Build instructions

This is a simple Maven project. Build with:

```bash
mvn verify
```

## Release instructions

The artifact is deployed to Sonatype's [Maven Central](https://central.sonatype.com/).

The actual repository URL is https://s01.oss.sonatype.org/, with server Id `ossrh` and requires credentials to deploy
artifacts manually.

But it is strongly recommended to only use [GitHub Actions "Release to Maven Central"](actions/workflows/release.yml) to perform a release:

* Manually trigger the "Release" workflow
* Specify the version being released and the next version number (SNAPSHOT)
* Release the corresponding staging repository on [Sonatype's Nexus server](https://s01.oss.sonatype.org/)
* Merge the PR that has been created to prepare the next version

## License

License is GNU General Lesser Public License (LGPL) version 3.0. Each source file includes the LGPL-3 header (build will fail otherwise). To update source files with the proper header, simply execute the below command:

```bash
mvn license:update-file-header
```
