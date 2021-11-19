package com.emarques.SpringSecurityJWT.controller;

import com.emarques.SpringSecurityJWT.model.UsuarioModel;
import com.emarques.SpringSecurityJWT.repository.UsuarioRepository;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/usuario")
@AllArgsConstructor
public class UsuarioController {

    private UsuarioRepository repository;

    @GetMapping("/listarTodos")
    public ResponseEntity<List<UsuarioModel>> listarTodos(){
        return ResponseEntity.ok(repository.findAll());
    }

    @PostMapping("/salvar")
    public ResponseEntity<UsuarioModel> salvar(@RequestBody UsuarioModel usuario){
        return ResponseEntity.ok(repository.save(usuario));
    }
}
