package br.com.JonathOliveira.todolist.task;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.JonathOliveira.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            var servletPath = request.getServletPath();

            if ("/tasks/".equals(servletPath)) {

                var authorization = request.getHeader("Authorization");

                if (authorization != null && authorization.startsWith("Basic")) {
                    var authEncoded = authorization.substring("Basic".length()).trim();

                    byte[] authDecode = Base64.getDecoder().decode(authEncoded);

                    var authString = new String(authDecode);

                    String[] credentials = authString.split(":");

                    String username = credentials[0];
                    String password = credentials[1];

                    var user = this.userRepository.findByUsername(username);

                    if (user != null) {
                        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                        if (passwordVerify.verified) {
                            filterChain.doFilter(request, response);
                            return;
                        }
                    }
                }

                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Usuário não autorizado");

            } else {
                filterChain.doFilter(request, response);
            }
        } catch (Exception e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Erro interno no servidor: " + e.getMessage());
        }
    }
}