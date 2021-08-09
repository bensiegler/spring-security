package org.springframework.security.web.authentication.twofa.repositories;



import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;

import javax.sql.DataSource;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DatabaseTwoFactorAuthCodeRepository implements TwoFactorAuthCodeRepository {

    public static final String GET_TWO_FACTOR_CODE_BY_SESSION_ID = "SELECT * FROM two_factor_authentication_codes WHERE session_id = ?;";
    public static final String REMOVE_TWO_FACTOR_CODE_BY_SESSION_ID = "DELETE FROM two_factor_authentication_codes WHERE session_id = ?;";
    public static final String INSERT_TWO_FACTOR_CODE = "INSERT INTO two_factor_authentication_codes (session_id, two_factor_code, username, time_created) VALUES (?, ?, ?, ?);";

    private String getTwoFactorCodeBySessionIdQuery = GET_TWO_FACTOR_CODE_BY_SESSION_ID;
    private String removeTwoFactorCodeQuery = REMOVE_TWO_FACTOR_CODE_BY_SESSION_ID;
    private String insertTwoFactorCode = INSERT_TWO_FACTOR_CODE;

	private DataSource dataSource;

	public DatabaseTwoFactorAuthCodeRepository(DataSource dataSource) {
		this.dataSource = dataSource;
	}

	@Override
    public void insertCode(SignInAttempt code) {
        try {
            PreparedStatement statement = getPreparedStatement(insertTwoFactorCode);

            statement.setString(1, code.getSessionId());
            statement.setString(2, code.getTwoFactorCode());
            statement.setString(3, code.getUsername());
            statement.setLong(4, code.getTime().getTime());

            statement.execute();
        }catch(SQLException e) {
            throw new RepositoryHandlingException(e.getMessage(), e.getCause());
        }
    }

    @Override
    public SignInAttempt getCode(String sessionId) {
		ResultSet resultSet;
		try {
            PreparedStatement statement = getPreparedStatement(getTwoFactorCodeBySessionIdQuery);

            statement.setString(1, sessionId);

            resultSet = statement.executeQuery();
            resultSet.next();
		}catch (SQLException e) {
			throw new RepositoryHandlingException(e.getMessage(), e.getCause());
		}

		try {
			return new SignInAttempt
					(
							sessionId,
							resultSet.getString("two_factor_code"),
							resultSet.getString("username"),
							resultSet.getLong("time_created")
					);
		}catch(SQLException e) {
			return null;
		}
    }

    @Override
    public void removeCode(SignInAttempt code) {
        removeCode(code.getSessionId());
    }

    @Override
    public void removeCode(String sessionId) {
        try {
            PreparedStatement statement = getPreparedStatement(removeTwoFactorCodeQuery);

            statement.setString(1, sessionId);

            statement.execute();
        }catch (SQLException e) {
            throw new RepositoryHandlingException(e.getMessage(), e.getCause());
        }
    }

    //TODO do these connections ever get released? Or do i have to manually release?
    private PreparedStatement getPreparedStatement(String query) throws SQLException {
        return dataSource.getConnection().prepareStatement(query);
    }

    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void setGetTwoFactorCodeBySessionIdQuery(String getTwoFactorCodeBySessionIdQuery) {
        this.getTwoFactorCodeBySessionIdQuery = getTwoFactorCodeBySessionIdQuery;
    }

    public void setRemoveTwoFactorCodeQuery(String removeTwoFactorCodeQuery) {
        this.removeTwoFactorCodeQuery = removeTwoFactorCodeQuery;
    }

    public void setInsertTwoFactorCode(String insertTwoFactorCode) {
        this.insertTwoFactorCode = insertTwoFactorCode;
    }

    public String getGetTwoFactorCodeBySessionIdQuery() {
        return getTwoFactorCodeBySessionIdQuery;
    }

    public String getRemoveTwoFactorCodeQuery() {
        return removeTwoFactorCodeQuery;
    }

    public String getInsertTwoFactorCode() {
        return insertTwoFactorCode;
    }
}
