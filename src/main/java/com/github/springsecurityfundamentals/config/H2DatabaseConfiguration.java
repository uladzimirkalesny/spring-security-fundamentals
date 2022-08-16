package com.github.springsecurityfundamentals.config;

import org.h2.tools.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.SQLException;

@Configuration
public class H2DatabaseConfiguration {

    private static final String INIT_METHOD = "start";
    private static final String DESTROY_METHOD = "stop";
    private static final String[] ARGS = new String[]{"-tcp", "-tcpAllowOthers", "-tcpPort", "9092"};

    @Bean(initMethod = INIT_METHOD, destroyMethod = DESTROY_METHOD)
    public Server inMemoryH2DatabaseServer() throws SQLException {
        return Server.createTcpServer(ARGS);
    }

}
