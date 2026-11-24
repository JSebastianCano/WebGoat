/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;

@ExtendWith(MockitoExtension.class)
class Assignment5SecurityTest {

  @Mock private LessonDataSource dataSource;
  @Mock private Flags flags;
  @Mock private Connection connection;
  @Mock private PreparedStatement statement;
  @Mock private ResultSet resultSet;

  private Assignment5 assignment;

  @BeforeEach
  void setUp() {
    assignment = new Assignment5(dataSource, flags);
  }

  @Test
  void rejectsOtherUsersBeforeDatabaseAccess() throws Exception {
    AttackResult result = assignment.login("Tom", "any-password");

    assertThat(result.isLessonCompleted()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("user.not.larry");
    verifyNoInteractions(dataSource);
  }

  @Test
  void rejectsIncorrectPassword() throws Exception {
    when(dataSource.getConnection()).thenReturn(connection);
    when(connection.prepareStatement(
            "select password from challenge_users where userid = ? and password = ?"))
        .thenReturn(statement);
    when(statement.executeQuery()).thenReturn(resultSet);
    when(resultSet.next()).thenReturn(false);

    AttackResult result = assignment.login("Larry", "wrong-password");

    assertThat(result.isLessonCompleted()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("challenge.close");
    verify(statement).setString(1, "Larry");
    verify(statement).setString(2, "wrong-password");
    verifyNoInteractions(flags);
  }

  @Test
  void rejectsBlankCredentialsBeforeDatabaseAccess() throws Exception {
    AttackResult missingUsername = assignment.login("", "any-password");
    AttackResult missingPassword = assignment.login("Larry", " ");

    assertThat(missingUsername.isLessonCompleted()).isFalse();
    assertThat(missingUsername.getFeedback()).isEqualTo("required4");
    assertThat(missingPassword.isLessonCompleted()).isFalse();
    assertThat(missingPassword.getFeedback()).isEqualTo("required4");
    verifyNoInteractions(dataSource);
  }

  @Test
  void hidesDatabaseFailureDetailsFromTheResponse() throws Exception {
    when(dataSource.getConnection()).thenThrow(new SQLException("sensitive database detail"));

    AttackResult result = assignment.login("Larry", "any-password");

    assertThat(result.isLessonCompleted()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("challenge.error");
    assertThat(result.getOutput()).isNull();
    verifyNoInteractions(flags);
  }
}
