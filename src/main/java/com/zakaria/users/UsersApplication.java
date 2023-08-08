package com.zakaria.users;

import com.zakaria.users.config.RsaKeysConfig;
import com.zakaria.users.services.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)
public class UsersApplication {

	public static void main(String[] args) {
		SpringApplication.run(UsersApplication.class, args);
	}
	@Bean
	PasswordEncoder passwordEncoder () {
		return new BCryptPasswordEncoder();
	}


	@Bean
	CommandLineRunner commandLineRunnerUserDetails(AccountService appAcocountService) {
		return args -> {

			// method personalize
			//appAcocountService.addNewRole("USER");
			//appAcocountService.addNewRole("ADMIN");

			//appAcocountService.addNewUser("user1", "1234", "user1@gmail.com", "1234");
			//appAcocountService.addNewUser("user2", "1234", "user2@gmail.com", "1234");
			//appAcocountService.addNewUser("admin", "1234", "admin@gmail.com", "1234");


			//appAcocountService.attachRoleToUser("user1", "USER");
			// appAcocountService.attachRoleToUser("user2", "USER");
			// appAcocountService.attachRoleToUser("admin", "USER");
			// appAcocountService.attachRoleToUser("admin", "ADMIN");

		};
	}
}
