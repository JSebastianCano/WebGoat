/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class Assignment5 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;
  private final Flags flags;

  @PostMapping("/challenge/5")
  @ResponseBody
  public AttackResult login(
      @RequestParam("username_login") String usernameLogin,
      @RequestParam("password_login") String passwordLogin)
      throws Exception {
    if (!StringUtils.hasText(usernameLogin) || !StringUtils.hasText(passwordLogin)) {
      return failed(this).feedback("required4").build();
    }
    if (!"Larry".equals(usernameLogin)) {
      return failed(this).feedback("user.not.larry").feedbackArgs(usernameLogin).build();
    }
    try (var connection = dataSource.getConnection()) {
      try (PreparedStatement statement =
          connection.prepareStatement(
              "select password from challenge_users where userid = ? and password = ?")) {
        statement.setString(1, usernameLogin);
        statement.setString(2, passwordLogin);

        try (ResultSet resultSet = statement.executeQuery()) {
          if (resultSet.next()) {
            return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(5)).build();
          } else {
            return failed(this).feedback("challenge.close").build();
          }
        }
      }
    } catch (SQLException exception) {
      log.error("Database failure while verifying Challenge 5 login", exception);
      return failed(this).feedback("challenge.error").build();
    }
  }
}
