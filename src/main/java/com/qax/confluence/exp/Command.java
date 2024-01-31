package com.qax.confluence.exp;

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.converters.FileConverter;

import java.io.File;

public class Command {

    @Parameter(names = {"--url", "-u"}, description = "target url", validateWith = UrlValidator.class)
    public String url;

    @Parameter(names = {"--cve", "-c"}, description = "choice confluence from cve-2021-26085, cve-2022-26134", validateWith = CVEValidator.class)
    public String cve;

    @Parameter(names = {"--attack", "-a"}, description = "choice attack method from behinder,godzilla,custom,addAdmin,getCookie", validateWith = AttackValidator.class)
    public String attack = "custom";

    @Parameter(names = {"--help", "-h"}, description = "Print usage", help = true)
    public boolean help;

    @Parameter(names = {"--input", "-i"}, description = "input custom file path", validateWith = FileValidator.class, converter = FileConverter.class)
    File input;

    @Parameter(names = {"--classname", "-cl"}, description = "input custom classname")
    String classname;

    public static class FileValidator implements IParameterValidator{

        @Override
        public void validate(String name, String value) throws ParameterException {
            File file = new File(value);
            if (!file.exists()) {
                throw new ParameterException("File " + value + " does not exist");
            }
        }
    }

    public static class CVEValidator implements IParameterValidator {

        @Override
        public void validate(String name, String value) throws ParameterException {
            if (!isValidInput(value)) {
                throw new ParameterException("Please choose from cve-2021-26085, cve-2022-26134");
            }
        }

        private boolean isValidInput(String value) {
            return value.equalsIgnoreCase("cve-2021-26085") || value.equalsIgnoreCase("cve-2022-26134");
        }
    }

    public static class UrlValidator implements IParameterValidator {

        @Override
        public void validate(String name, String value) throws ParameterException {
            if (value.isEmpty()) {
                throw new ParameterException("Please input url");
            }
        }
    }

    public static class AttackValidator implements IParameterValidator{

        @Override
        public void validate(String name, String value) throws ParameterException {
            if (!isValidInput(value)) {
                throw new ParameterException("Please choose from behinder,godzilla,custom,addAdmin,getCookie");
            }
        }

        private boolean isValidInput(String value) {
            return value.equalsIgnoreCase("behinder") || value.equalsIgnoreCase("godzilla") || value.equalsIgnoreCase("addAdmin") || value.equalsIgnoreCase("getCookie") || value.equalsIgnoreCase("custom");
        }
    }
}