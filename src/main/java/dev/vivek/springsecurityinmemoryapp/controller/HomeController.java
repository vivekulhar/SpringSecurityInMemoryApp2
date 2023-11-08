package dev.vivek.springsecurityinmemoryapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class HomeController {
    @GetMapping("/home")
    public String getHomePage(){
        return "homePage";
    }
    @GetMapping("/welcome")
    public String getWelcomePage(){
        return "welcomePage";
    }
    @GetMapping("/admin")
    public String getAdminPage(){
        return "adminPage";
    }

    @GetMapping("/emp")
    public String getEmpPage(){
        return "empPage";
    }

    @GetMapping("/mgr")
    public String getMgrPage(){
        return "mgrPage";
    }
    @GetMapping("/common")
    public String getCommonPage(){
        return "commonPage";
    }
    @GetMapping("/accessDenied")
    public String getAccessDeniedPage(){
        return "accessDeniedPage";
    }
    @GetMapping("/logout")
    public String getLogoutPage(){
        return "logoutPage";
    }
}
