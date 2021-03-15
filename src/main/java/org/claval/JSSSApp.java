package org.claval;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Collectors;

import com.codahale.shamir.Scheme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;

@SpringBootApplication
public class JSSSApp  {

	public static void main(String[] args) {
		SpringApplication.run(JSSSApp.class, args);
	}

	@Component
 	class JSSSCommandLineRunner implements CommandLineRunner {
    Logger logger = LoggerFactory.getLogger(JSSSCommandLineRunner.class);    

    public void run(String... args) {
		String strArgs = Arrays.stream(args).collect(Collectors.joining("|"));
    	logger.info("JSSS started with arguments:" + strArgs);
		if ( args.length < 3 ){
			throw new InvalidParameterException("Usage : [shard|join] N K");
		}
		if ( !"shard".equals(args[0]) && !"join".equals(args[0]) ){
			throw new InvalidParameterException("Usage : [shard|join] N K");
		}


		if(args[0].equals("shard")){
			try {
				JSSS jsss = new JSSS(new Scheme(new SecureRandom(), Integer.parseInt(args[1]), Integer.parseInt(args[2])));
				jsss.shard();
			} catch (Exception e) {
				logger.error("error during shard operation:", e);
			}
		}
		if(args[0].equals("join")){
			try {
				JSSS jsss = new JSSS(new Scheme(new SecureRandom(), Integer.parseInt(args[1]), Integer.parseInt(args[2])));
				jsss.join( Arrays.copyOfRange(args, 3, args.length));
			} catch (Exception e) {
				logger.error("error during shard operation:", e);
			}

		}
    }
} 
}
