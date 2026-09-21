package com.barrhopp.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class BarrhoppApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(BarrhoppApiApplication.class, args);
    }

}
