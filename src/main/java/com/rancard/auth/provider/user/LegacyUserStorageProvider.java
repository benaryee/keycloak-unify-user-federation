package com.rancard.auth.provider.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.*;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LegacyUserStorageProvider
		implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, UserQueryProvider {

	private static final Logger log = LoggerFactory.getLogger(LegacyUserStorageProvider.class);

	private KeycloakSession session;

	private ComponentModel model;


	public LegacyUserStorageProvider(KeycloakSession session, ComponentModel model) {
		this.session = session;
		this.model = model;
	}

	@Override
	public void close() {
		log.info("Close");
	}

	@Override
	public int getUsersCount(RealmModel realm) {
		log.info("getUsersCount: realm={}", realm.getName());
		try (Connection c = LegacyDBConnection.getConnection(this.model)) {
			Statement st = c.createStatement();
			st.execute("select count(*) from users");
			ResultSet rs = st.getResultSet();
			rs.next();

			log.info("Users Count : {}", rs.getInt(1));

			return rs.getInt(1);
		} catch (SQLException ex) {
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}

	@Override
	public List<UserModel> getUsers(RealmModel realm) {
		return getUsers(realm, 0, 1000);
	}

	@Override
	public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
		log.info("getUsers: realm={}", realm.getName());

		try (Connection c = LegacyDBConnection.getConnection(this.model)) {
			log.info("About to execute SQL statement");
			PreparedStatement st = c.prepareStatement(
					"select msisdn,full_name, email from users order by full_name limit ? offset ?");
			st.setInt(1, maxResults);
			st.setInt(2, firstResult);
			st.execute();
			ResultSet rs = st.getResultSet();

			log.info("Done executing SQL statement : {}", st);


			List<UserModel> users = new ArrayList<>();
			while (rs.next()) {
				users.add(mapUser(realm, rs));
			}
			return users;
		} catch (SQLException ex) {
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}

	@Override
	public List<UserModel> searchForUser(String search, RealmModel realm) {
		return searchForUser(search, realm, 0, 1000);
	}

	@Override
	public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
		log.info("searchForUser: realm={}", realm.getName());

		try (Connection c = LegacyDBConnection.getConnection(this.model)) {
			PreparedStatement st = c.prepareStatement(
					"select msisdn,full_name, email from users where full_name like ? order by full_name limit ? offset ?");
			st.setString(1, search);
			st.setInt(2, maxResults);
			st.setInt(3, firstResult);
			st.execute();
			ResultSet rs = st.getResultSet();
			List<UserModel> users = new ArrayList<>();
			while (rs.next()) {
				users.add(mapUser(realm, rs));
			}
			return users;
		} catch (SQLException ex) {
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}

	@Override
	public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
		return searchForUser(params, realm, 0, 1000);
	}

	@Override
	public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult,
										 int maxResults) {
		return getUsers(realm, firstResult, maxResults);
	}

	public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
		List<UserModel> users = getUsers(realm,firstResult,maxResults);

		// Apply pagination if necessary
		if (firstResult != null && maxResults != null) {
			users = users.stream()
					.skip(firstResult)
					.limit(maxResults)
					.collect(Collectors.toList());
		}

		return users.stream();
	}
	@Override
	public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
		return Collections.emptyList();
	}

	@Override
	public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
		return Collections.emptyList();
	}

	@Override
	public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
		return Collections.emptyList();
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		log.info("supportsCredentialType({})", credentialType);
		return PasswordCredentialModel.TYPE.endsWith(credentialType);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		log.info("isConfiguredFor(realm={},user={},credentialType={})", realm.getName(), user.getUsername(),
				credentialType);
		return supportsCredentialType(credentialType);
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
		log.info("isValid(realm={},user={},credentialInput.type={})", realm.getName(), user.getUsername(),
				credentialInput.getType());
		if (!this.supportsCredentialType(credentialInput.getType())) {
			return false;
		}
		StorageId sid = new StorageId(user.getId());
		String username = sid.getExternalId();

		try (Connection c = LegacyDBConnection.getConnection(this.model)) {
			PreparedStatement st = c.prepareStatement("select password from users where username = ?");
			st.setString(1, username);
			st.execute();
			ResultSet rs = st.getResultSet();
			if (rs.next()) {
				String pwd = rs.getString(1);
				return pwd.equals(credentialInput.getChallengeResponse());
			} else {
				return false;
			}
		} catch (SQLException ex) {
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}

	@Override
	public UserModel getUserById(String id, RealmModel realm) {
		log.info("getUserById({})", id);
		StorageId sid = new StorageId(id);
		return getUserByUsername(sid.getExternalId(), realm);
	}

	@Override
	public UserModel getUserByUsername(String username, RealmModel realm) {
		log.info("getUserByUsername({})", username);
		try (Connection c = LegacyDBConnection.getConnection(this.model)) {
			PreparedStatement st = c.prepareStatement(
					"select msisdn,full_name, email from users order by full_name where username = ?");
			st.setString(1, username);
			st.execute();
			ResultSet rs = st.getResultSet();
			if (rs.next()) {
				return mapUser(realm, rs);
			} else {
				return null;
			}
		} catch (SQLException ex) {
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}

	@Override
	public UserModel getUserByEmail(String email, RealmModel realm) {
		log.info("getUserByEmail({})", email);
		try (Connection c = LegacyDBConnection.getConnection(this.model)) {
			PreparedStatement st = c.prepareStatement(
					"select msisdn,full_name, email from users order by full_name where email = ?");
			st.setString(1, email);
			st.execute();
			ResultSet rs = st.getResultSet();
			if (rs.next()) {
				return mapUser(realm, rs);
			} else {
				return null;
			}
		} catch (SQLException ex) {
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}

	private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
		LegacyUser user = new LegacyUser.Builder(session, realm, model, rs.getString("full_name"))
				.email(rs.getString("email"))
				.firstName(rs.getString("full_name").split(" ")[0])
				.lastName(rs.getString("full_name").split(" ").length >= 2 ? rs.getString("full_name").split(" ")[1] : "")
				.build();
		return user;
	}


	private static void logResultSet(ResultSet resultSet) throws SQLException {
		log.info("Extracted log");
		while (resultSet.next()) {
			// Retrieve data from the result set
			int id = resultSet.getInt("id");
			String name = resultSet.getString("full_name");
			// ... Retrieve other columns as needed

			// Log the retrieved data
			log.info("ID: " + id + ", Name: " + name);
			// ... Log other columns as needed
		}
	}

	private static void getResultSetSize(ResultSet resultSet) throws SQLException {
		int size = 0;
		if (resultSet.last()) {
			size = resultSet.getRow();
			resultSet.beforeFirst();
		}
		log.info("Result set size: {}",size);

	}

}
