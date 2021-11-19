package com.emarques.SpringSecurityJWT.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.emarques.SpringSecurityJWT.data.DetalheUsuarioData;
import com.emarques.SpringSecurityJWT.model.UsuarioModel;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

//Responsável por autenticar o usuário e fazer a geração do Token JWT
@AllArgsConstructor
public class JWTAutenticarFilter extends UsernamePasswordAuthenticationFilter {

    public static final int TOKEN_EXPIRACAO = 600_000;
    public static final String TOKEN_SENHA = "896a66b7-c1d7-47d5-848f-9f33e0b0e903";
    private final AuthenticationManager authenticationManager;

    //Sobrescrita de um método que irá efetivamente executar a autenticação
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            //Converte o conteúdo do JSON para a classe usuarioModel
            UsuarioModel usuario = new ObjectMapper().readValue(request.getInputStream(), UsuarioModel.class);
            // Validação
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    usuario.getLogin(),
                    usuario.getPassword(),
                    new ArrayList<>()
            ));
        } catch (IOException e) {
            throw new RuntimeException("Falha ao autenticar usuario", e);
        }
    }

    //Metodo que será executado caso haja sucesso na autenticação.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        //Retorna o resultado da autenticação fazendo o typecast "()", e armazena no objeto usuarioData
        DetalheUsuarioData usuarioData = (DetalheUsuarioData) authResult.getPrincipal();

        //Geração do Token, usando o auth0
        String token = JWT.create()
                // Informa o nome do usuário
                .withSubject(usuarioData.getUsername())
                // Define expiração, somando o tempo de expiração com milissegundos atuais
                .withExpiresAt(new Date(
                                System.currentTimeMillis() + TOKEN_EXPIRACAO))
                // Assinatura do token através de uma senha GUID, para torná-lo único.
                .sign(Algorithm.HMAC512(TOKEN_SENHA));

        //Registro do Token no corpo da página
        response.getWriter().write(token);
        response.getWriter().flush();
    }
}
