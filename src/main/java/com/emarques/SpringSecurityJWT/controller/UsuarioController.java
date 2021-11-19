package com.emarques.SpringSecurityJWT.controller;

import com.emarques.SpringSecurityJWT.model.UsuarioModel;
import com.emarques.SpringSecurityJWT.repository.UsuarioRepository;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/usuario")
@AllArgsConstructor
public class UsuarioController {

    private final PasswordEncoder encoder;
    private final UsuarioRepository repository;

    @GetMapping("/listarTodos")
    public ResponseEntity<List<UsuarioModel>> listarTodos(){
        return ResponseEntity.ok(repository.findAll());
    }

    @PostMapping("/salvar")
    public ResponseEntity<UsuarioModel> salvar(@RequestBody UsuarioModel usuario){
        usuario.setPassword(encoder.encode(usuario.getPassword()));
        return ResponseEntity.ok(repository.save(usuario));
    }

    @GetMapping("/validarSenha")
    public ResponseEntity<Boolean> validarSenha (@RequestParam String login,
                                                 @RequestParam String password){

        //Verifica se o usuário existe. Caso não, retorna "não autorizado".
        Optional<UsuarioModel> optUsuario = repository.findByLogin(login);
        if (optUsuario.isEmpty()){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(false);
        }

        //Verifica se a senha é válida. Define o status HTTP baseado na resposta.
        boolean valid = encoder.matches(password, optUsuario.get().getPassword());
        HttpStatus status = (valid) ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;

        return ResponseEntity.status(status).body(valid);
    }
}
