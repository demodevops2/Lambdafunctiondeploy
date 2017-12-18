/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.amazonaws.serverless.sample.spring;

import com.amazonaws.serverless.sample.spring.model.LoginVO;
import com.amazonaws.serverless.sample.spring.model.Pet;
import com.amazonaws.serverless.sample.spring.model.PetData;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.security.Principal;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@EnableWebMvc
public class PetsController {
	
	
	@RequestMapping(path = "/pets", method = RequestMethod.POST)
    public Pet createPet(@RequestBody Pet newPet) {
        if (newPet.getName() == null || newPet.getBreed() == null) {
            return null;
        }

        Pet dbPet = newPet;
        dbPet.setId(UUID.randomUUID().toString());
        return dbPet;
    }

    @RequestMapping(path = "/pets", method = RequestMethod.GET)
    public Pet[] listPets(@RequestParam("limit") Optional<Integer> limit, Principal principal) {
        System.out.println(principal.getName());
        int queryLimit = 10;
        if (limit.isPresent()) {
            queryLimit = limit.get();
        }

        Pet[] outputPets = new Pet[queryLimit];

        for (int i = 0; i < queryLimit; i++) {
            Pet newPet = new Pet();
            newPet.setId(UUID.randomUUID().toString());
            newPet.setName(PetData.getRandomName());
            newPet.setBreed(PetData.getRandomBreed());
            newPet.setDateOfBirth(PetData.getRandomDoB());
            outputPets[i] = newPet;
        }

        return outputPets;
    }

    @RequestMapping(path = "/pets/{petId}", method = RequestMethod.GET)
    public Pet listPets() {
        Pet newPet = new Pet();
        newPet.setId(UUID.randomUUID().toString());
        newPet.setBreed(PetData.getRandomBreed());
        newPet.setDateOfBirth(PetData.getRandomDoB());
        newPet.setName(PetData.getRandomName());
        return newPet;
    }
    
    @Autowired
	CognitoHelper cognitoHelper;
	
	
	
	@RequestMapping(value = "/avail")
	public String init() {
		return " Auth Server micro service";
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public String login(@RequestBody LoginVO loginVO, HttpServletRequest req, HttpServletResponse resp) throws Exception {
		System.out.println("Start : login" + loginVO.getUserName() +"     " + loginVO.getPassword());
		String response = "";
		try {
			response = cognitoHelper.validateUser(loginVO.getUserName(), loginVO.getPassword());
			System.out.println("Responce Token : " + response);
		} catch (Exception e) {
			System.out.println("Error : "+ e.getMessage());
		}
		return response;
	}

}
