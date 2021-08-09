package org.springframework.security.web.authentication.twofa.repositories;

public class RepositoryHandlingException extends RuntimeException {

    public RepositoryHandlingException() {
    }

    public RepositoryHandlingException(String message) {
        super(message);
    }

    public RepositoryHandlingException(String message, Throwable cause) {
        super(message, cause);
    }

    public RepositoryHandlingException(Throwable cause) {
        super(cause);
    }

}
