package com.emarques.SpringSecurityJWT.services;

import com.emarques.SpringSecurityJWT.data.DetalheUsuarioData;
import com.emarques.SpringSecurityJWT.model.UsuarioModel;
import com.emarques.SpringSecurityJWT.repository.UsuarioRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@AllArgsConstructor
public class DetalheUsuarioServiceImpl implements UserDetailsService {

    private final UsuarioRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UsuarioModel> usuario = repository.findByLogin(username);
        if (usuario.isEmpty()){
            throw new UsernameNotFoundException("Usuário ["+username+"] não encontrado!");
        }

        return new DetalheUsuarioData(usuario);
    }
}
