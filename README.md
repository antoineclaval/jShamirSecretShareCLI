# Purpose

JSSS is a Java implementation of Shamir's Secret Share. It allows : 

- The generation of a classic RSA key-pair, but the private key can be segmented in a set of N elements.
- At decryption time, at least K of those private-key segments are needed in order to reassemble the private key successfully. 

It allows collaborative workflows of the type best described as : "Like the nuclear bomb code".

# Usage

### Buid 

mvn compile

### Run

mvn spring-boot:run -Dspring-boot.run.arguments="[shard|join] N K"

Exemples : 

- mvn spring-boot:run -Dspring-boot.run.arguments="shard 2 5"
then 
- mvn spring-boot:run -Dspring-boot.run.arguments="join 2 5"



### Tests 

mvn test 

---

## Reference 

- [Shamir's Secret Sharing Implementation by Coda Hale ( Apache 2.0 )](https://github.com/codahale/shamir)



For further reference, please consider the following sections:

* [Official Apache Maven documentation](https://maven.apache.org/guides/index.html)
* [Spring Boot Maven Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/2.4.3/maven-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/2.4.3/maven-plugin/reference/html/#build-image)




