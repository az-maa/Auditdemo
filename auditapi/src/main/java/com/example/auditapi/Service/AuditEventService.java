package com.example.auditapi.Service;

import com.example.auditapi.Model.AuditEvent;
import com.example.auditapi.Repository.AuditEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class AuditEventService {

    @Autowired
    private AuditEventRepository repository;

    
    public List<AuditEvent> getAllEvents() {
        return repository.findAll();
    }

   
    public Optional<AuditEvent> getEventById(Long id) {
        return repository.findById(id);
    }

    
    public AuditEvent createEvent(AuditEvent event) {
        return repository.save(event);
    }

   
    public List<AuditEvent> getEventsByType(String eventType) {
        return repository.findByEventType(eventType);
    }

    
    public List<AuditEvent> getEventsByUser(String userId) {
        return repository.findByUserId(userId);
    }

    
    public List<AuditEvent> getEventsByStatus(String status) {
        return repository.findByStatus(status);
    }

    
    public List<AuditEvent> getEventsBySeverity(String severity) {
        return repository.findBySeverity(severity);
    }

    
    public List<AuditEvent> getEventsByDateRange(LocalDateTime start, LocalDateTime end) {
        return repository.findByTimestampBetween(start, end);
    }

    
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        
        stats.put("totalEvents", repository.count());

        
        stats.put("loginEvents", repository.countByEventType("LOGIN"));
        stats.put("logoutEvents", repository.countByEventType("LOGOUT"));
        stats.put("dataAccessEvents", repository.countByEventType("DATA_ACCESS"));
        stats.put("transferEvents", repository.countByEventType("TRANSFER"));
        stats.put("errorEvents", repository.countByEventType("ERROR"));

        
        stats.put("successEvents", repository.countByStatus("SUCCESS"));
        stats.put("failureEvents", repository.countByStatus("FAILURE"));
        stats.put("pendingEvents", repository.countByStatus("PENDING"));

       
        stats.put("infoEvents", repository.countBySeverity("INFO"));
        stats.put("warningEvents", repository.countBySeverity("WARNING"));
        stats.put("errorSeverityEvents", repository.countBySeverity("ERROR"));
        stats.put("criticalEvents", repository.countBySeverity("CRITICAL"));

        return stats;
    }
}