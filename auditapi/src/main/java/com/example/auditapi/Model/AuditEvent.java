package com.example.auditapi.Model;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_events")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 50)
    private String eventType;  

    @Column(nullable = false,length = 100)
    private String userId;

    @Column(nullable = false)
    private String action;

    private String resource;

    @Column(length = 45)
    private String ipAddress;

    @Column(nullable = false, length = 20)
    private String status;  

    @Column(length = 20)
    private String severity;  
    @Column(length = 1000)
    private String details;

    @PrePersist
    protected void onCreate() {
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }
}