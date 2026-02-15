package com.example.auditapi.Controller;
import com.example.auditapi.Model.AuditEvent;
import com.example.auditapi.Service.AuditEventService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit")
@CrossOrigin(origins = "*")
public class AuditEventController {

    @Autowired
    private AuditEventService service;

    
    @GetMapping("/events")
    public ResponseEntity<List<AuditEvent>> getAllEvents() {
        return ResponseEntity.ok(service.getAllEvents());
    }

   
    @GetMapping("/events/{id}")
    public ResponseEntity<AuditEvent> getEventById(@PathVariable Long id) {
        return service.getEventById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    
    @PostMapping("/events")
    public ResponseEntity<AuditEvent> createEvent(@RequestBody AuditEvent event) {
        AuditEvent created = service.createEvent(event);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    
    @GetMapping("/events/type/{eventType}")
    public ResponseEntity<List<AuditEvent>> getEventsByType(@PathVariable String eventType) {
        return ResponseEntity.ok(service.getEventsByType(eventType));
    }

    
    @GetMapping("/events/user/{userId}")
    public ResponseEntity<List<AuditEvent>> getEventsByUser(@PathVariable String userId) {
        return ResponseEntity.ok(service.getEventsByUser(userId));
    }

    
    @GetMapping("/events/status/{status}")
    public ResponseEntity<List<AuditEvent>> getEventsByStatus(@PathVariable String status) {
        return ResponseEntity.ok(service.getEventsByStatus(status));
    }

    
    @GetMapping("/events/severity/{severity}")
    public ResponseEntity<List<AuditEvent>> getEventsBySeverity(@PathVariable String severity) {
        return ResponseEntity.ok(service.getEventsBySeverity(severity));
    }

    
    @GetMapping("/events/search")
    public ResponseEntity<List<AuditEvent>> searchByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
        return ResponseEntity.ok(service.getEventsByDateRange(start, end));
    }

    
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        return ResponseEntity.ok(service.getStatistics());
    }
}