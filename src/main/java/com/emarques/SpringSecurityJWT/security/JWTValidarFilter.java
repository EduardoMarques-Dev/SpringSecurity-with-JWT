package com.emarques.SpringSecurityJWT.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

//Responsável por validar o Token
public class JWTValidarFilter extends BasicAuthenticationFilter {

    public static final String HEADER_ATRIBUTO = "Authorization";
    public static final String ATRIBUTO_PREFIXO = "Bearer ";


    public JWTValidarFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    //Responsável por interceptar o cabeçalho da requisição
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        //Procura se há no cabeçalho o atributo "Authorization" e um prefixo "Bearer" informanto o tipo do token
        String atributo = request.getHeader(HEADER_ATRIBUTO);
        if ((atributo == null) &&(!atributo.startsWith(ATRIBUTO_PREFIXO))){
            chain.doFilter(request,response);
            return;
        }

        //Remove o prefixo do token
        String token = atributo.replace(ATRIBUTO_PREFIXO, "");

        UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(token);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    //Responsável por fazer a leitura do Token e retornar os dados do usuário, para que possam verificar se ele é válido
    private UsernamePasswordAuthenticationToken getAuthenticationToken(String token){
        //Variável que irá extrair o nome do usuário
        String usuario = JWT
                //Efetua uma requisição usando a GUID criada no 'autenticador'
                .require(Algorithm.HMAC512(JWTAutenticarFilter.TOKEN_SENHA))
                //Cria a leitura do token
                .build()
                //Verifica o conteúdo token
                .verify(token)
                //Onde se encontra o nome do usuário
                .getSubject();

        if (usuario == null){
            return null;
        }

        // Retorna o token com o nome do usuário, senha (nula), e lista de permissões (vazia)
        return new UsernamePasswordAuthenticationToken(usuario, null, new ArrayList<>());

    }
}
