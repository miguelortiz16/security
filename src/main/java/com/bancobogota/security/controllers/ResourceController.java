package com.bancobogota.security.controllers;



import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/resource")
public class ResourceController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin content";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public String userAccess() {
        return "User content";
    }

    @GetMapping("/data")
    @PreAuthorize("hasAuthority('SCOPE_read') and #userId == authentication.name")
    public String getData(@RequestParam String userId) {
        return "Data for user: " + userId;
    }
}
