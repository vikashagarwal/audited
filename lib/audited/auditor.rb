module Audited
  # Specify this act if you want changes to your model to be saved in an
  # audit table.  This assumes there is an audits table ready.
  #
  #   class User < ActiveRecord::Base
  #     audited
  #   end
  #
  # To store an audit comment set model.audit_comment to your comment before
  # a create, update or destroy operation.
  #
  # See <tt>Audited::Auditor::ClassMethods#audited</tt>
  # for configuration options
  module Auditor #:nodoc:
    extend ActiveSupport::Concern

    CALLBACKS = [:audit_create, :audit_update, :audit_destroy]

    module ClassMethods
      # == Configuration options
      #
      #
      # * +only+ - Only audit the given attributes
      # * +except+ - Excludes fields from being saved in the audit log.
      #   By default, Audited will audit all but these fields:
      #
      #     [self.primary_key, inheritance_column, 'lock_version', 'created_at', 'updated_at']
      #   You can add to those by passing one or an array of fields to skip.
      #
      #     class User < ActiveRecord::Base
      #       audited except: :password
      #     end
      #
      # * +require_comment+ - Ensures that audit_comment is supplied before
      #   any create, update or destroy operation.
      #
      def audited(options = {})
        # don't allow multiple calls
        return if included_modules.include?(Audited::Auditor::AuditedInstanceMethods)

        extend Audited::Auditor::AuditedClassMethods
        include Audited::Auditor::AuditedInstanceMethods

        class_attribute :audit_associated_with,   instance_writer: false
        class_attribute :audited_options,       instance_writer: false
        attr_accessor :version, :audit_comment, :audit_username, :audit_user_id, :audit_domain_id, :audit_module_name, :audit_conversation_id, :audit_action_name, :audit_path

        self.audited_options = options
        normalize_audited_options

        self.audit_associated_with = audited_options[:associated_with]

        if audited_options[:comment_required]
          validates_presence_of :audit_comment, if: :auditing_enabled
          before_destroy :require_comment
        end

        has_many :audits, -> { order(version: :asc) }, as: :auditable, class_name: Audited.audit_class.name, inverse_of: :auditable
        Audited.audit_class.audited_class_names << to_s

        after_create :audit_create    if audited_options[:on].include?(:create)
        before_update :audit_update   if audited_options[:on].include?(:update)
        before_destroy :audit_destroy if audited_options[:on].include?(:destroy)

        # Define and set after_audit and around_audit callbacks. This might be useful if you want
        # to notify a party after the audit has been created or if you want to access the newly-created
        # audit.
        define_callbacks :audit
        set_callback :audit, :after, :after_audit, if: lambda { respond_to?(:after_audit, true) }
        set_callback :audit, :around, :around_audit, if: lambda { respond_to?(:around_audit, true) }

        enable_auditing
      end

      def has_associated_audits
        has_many :associated_audits, as: :associated, class_name: Audited.audit_class.name
      end
    end

    module AuditedInstanceMethods
      # Temporarily turns off auditing while saving.
      def save_without_auditing
        without_auditing { save }
      end

      # Executes the block with the auditing callbacks disabled.
      #
      #   @foo.without_auditing do
      #     @foo.save
      #   end
      #
      def without_auditing(&block)
        self.class.without_auditing(&block)
      end

      # Gets an array of the revisions available
      #
      #   user.revisions.each do |revision|
      #     user.name
      #     user.version
      #   end
      #
      def revisions(from_version = 1)
        return [] unless audits.from_version(from_version).exists?

        all_audits = audits.select([:audited_changes, :version]).to_a
        targeted_audits = all_audits.select { |audit| audit.version >= from_version }

        previous_attributes = reconstruct_attributes(all_audits - targeted_audits)

        targeted_audits.map do |audit|
          previous_attributes.merge!(audit.new_attributes)
          revision_with(previous_attributes.merge!(version: audit.version))
        end
      end

      # Get a specific revision specified by the version number, or +:previous+
      # Returns nil for versions greater than revisions count
      def revision(version)
        if version == :previous || self.audits.last.version >= version
          revision_with Audited.audit_class.reconstruct_attributes(audits_to(version))
        end
      end

      # Find the oldest revision recorded prior to the date/time provided.
      def revision_at(date_or_time)
        audits = self.audits.up_until(date_or_time)
        revision_with Audited.audit_class.reconstruct_attributes(audits) unless audits.empty?
      end

      # List of attributes that are audited.
      def audited_attributes
        attributes.except(*non_audited_columns)
      end

      #Start of custom method added made by Vikash
      def revision_for_range(from_date, to_date, from_version=1, comment='payment')
        audits = self.audits.where("DATE(created_at) >= ? AND DATE(created_at) <= ? AND version >= ? AND (comment = ? OR comment = ?)", from_date.to_date, to_date.to_date, from_version, 'payment', 'regular')
        return nil if audits.empty?

        audit = audits.last.revision
        audit.created_at = audits.last.created_at 
        audit.created_at = self.created_at if audit.created_at.nil?
        audit.end_of_trial = self.end_of_trial
        return audit
      end

      def audit_revisions_range(from_date_or_time, to_date_or_time,comment_type, from_version=1)
        audits = self.audits.where("DATE(created_at) >= ? AND DATE(created_at) <= ? AND comment = ? AND action != ? AND version >= ?", from_date_or_time, to_date_or_time, comment_type, 'create', from_version)
        return [] if audits.empty?
        audits
      end
      #End of custom method added made by Vikash

      protected

      def non_audited_columns
        self.class.non_audited_columns
      end

      def audited_columns
        self.class.audited_columns
      end

      def revision_with(attributes)
        dup.tap do |revision|
          revision.id = id
          revision.send :instance_variable_set, '@attributes', self.attributes if rails_below?('4.2.0')
          revision.send :instance_variable_set, '@new_record', destroyed?
          revision.send :instance_variable_set, '@persisted', !destroyed?
          revision.send :instance_variable_set, '@readonly', false
          revision.send :instance_variable_set, '@destroyed', false
          revision.send :instance_variable_set, '@_destroyed', false
          revision.send :instance_variable_set, '@marked_for_destruction', false
          Audited.audit_class.assign_revision_attributes(revision, attributes)

          # Remove any association proxies so that they will be recreated
          # and reference the correct object for this revision. The only way
          # to determine if an instance variable is a proxy object is to
          # see if it responds to certain methods, as it forwards almost
          # everything to its target.
          revision.instance_variables.each do |ivar|
            proxy = revision.instance_variable_get ivar
            if !proxy.nil? && proxy.respond_to?(:proxy_respond_to?)
              revision.instance_variable_set ivar, nil
            end
          end
        end
      end

      def rails_below?(rails_version)
        Gem::Version.new(Rails::VERSION::STRING) < Gem::Version.new(rails_version)
      end

      private

      #Start of custom method added made by Vikash
      def set_update_changes
        if defined? self.audit_additional_attributes
          return self.changes.merge(self.audit_additional_attributes)
        else
          return changes
        end
      end
      
       def set_audit_comment
        if self.respond_to?(:message)
          audit_comment = (self.message.present? ? self.message[0..100] : self.message)
        elsif self.respond_to?(:filename)
          audit_comment = self.filename
        elsif self.class.name == "Conversation" && changed_attributes.has_key?("created_by")
          old_user_id = audited_changes["created_by"].first
          new_user_id = audited_changes["created_by"].last
          audit_comment = "#{old_user_id},#{new_user_id}"
        elsif self.class.name =="Domain"
          if changed_attributes.has_key?("is_ldap_auth_enabled")
            if changed_attributes["is_ldap_auth_enabled"] == MConstants::YES
              audit_comment ="LDAP settings has been disabled"
            else
              audit_comment ="LDAP settings has been enabled"
            end
          elsif changed_attributes.has_key?("storage_location")
            audit_comment = "File storage location changed from #{audited_changes['storage_location'][0]} to #{audited_changes['storage_location'][1]}"
          end
        elsif self.respond_to?(:name)
          audit_comment = self.name
        elsif self.respond_to?(:title)
          audit_comment = self.title
        elsif self.class.name == 'FeedComment' and self.comment == ""
          audit_comment = self.response == '1' ? 'Poll replied as YES' : self.response == '2' ? 'Poll replied as NO' : 'Poll replied as MAYBE'
        elsif self.respond_to?(:comment)
          audit_comment = self.comment
        elsif self.respond_to?(:for_whom)
          audit_comment = self.for_whom
        elsif self.class.name == "DomainSetting"
          audit_comment = self.audit_comment == "T" ? "Notification Settings updated for all domain users and new users" : self.audit_comment == "A" ? "Notification Settings updated for all domain users, guest users and new users" : self.audit_comment == "F" ? "Notification Settings for new users updated" : ""
          audit_comment = "Dashboard Type" if changed_attributes.has_key?("dashboard_type")
        elsif self.class.name == "DomainPreference"
          if changed_attributes.has_key?("enable_super_password") || changed_attributes.has_key?("super_password")
            audit_comment = "Super Password"
          elsif changed_attributes.has_key?("enable_pin") || changed_attributes.has_key?("pin")
            audit_comment = "Admin Pin"
          else
            audit_comment = self.audit_comment(changed_attributes)
          end
        elsif self.class.name == "EcmRepository"
          if changed_attributes.has_key?("san_path")
            audit_comment = "San path modified"
          elsif changed_attributes.has_key?("s3_access_key") || changed_attributes.has_key?("s3_secret_key") || 
            changed_attributes.has_key?("s3_bucket_name") 
            audit_comment = "S3 account modified"
          elsif changed_attributes.has_key?("repository_login_id")
            audit_comment = "Box account modified"
          end
        else
          audit_comment = audit_comment
        end

        audit_comment
      end

      def set_conversation_id
        if self.respond_to?(:conversation_id)
          $conversation_id = nil
          $conversation_id = self.conversation_id
          audit_conversation_id = self.conversation_id
        elsif self.class.name == 'FeedComment'
          audit_conversation_id = self.feed.conversation_id
        elsif self.class.name == 'SitePage'
          audit_conversation_id = self.site.conversation.id
        elsif !(self.respond_to?(:conversation_id))
          return nil
        end
      end
      
      def set_username
        if self.audit_username.present?
          audit_username = self.audit_username
        elsif User.current.present?
          audit_username = User.current.email_id
        end
      end

      def set_user_id
        if self.audit_user_id.present?
          audit_user_id = self.audit_user_id
        elsif User.current.present?
          audit_user_id = User.current.id
        end
      end
      
      def set_domain_id
        if self.audit_domain_id.present?
          audit_domain_id = self.audit_domain_id
        elsif User.current.present?
          User.current.domain_id
        end
      end
      
      def set_module_name
        if self.class.name == 'Feed'
          self.audit_module_name = self.category == 'I' ? 'Idea' :  self.category == 'Q' ? 'Question' : self.category == 'O' ? 'Poll' : 'Feed'
        elsif self.class.name == 'Post'
          self.audit_module_name = self.conversation_id == nil ? "Blog" : self.is_announcement || self.is_company_announcement == true ? 'Announcement' : 'Post'
        elsif self.class.name == 'Conversation'
          audit_module_name = self.is_opportunity? ? 'Opportunity' : self.is_group? ? "Group" : self.is_project? ? "Project" : self.is_department? ? "Department" : 'Conversation'   
        elsif self.class.name == 'Task'
          audit_module_name = "Task"
        elsif self.class.name == 'TimeLog'
          audit_module_name = 'Time log'
        elsif self.class.name == 'Attachment'
          audit_module_name = self.kind == 'FL' ? 'Folder' : 'File' 
        elsif self.class.name == 'IdeaSession'
          audit_module_name = 'Idea Campaign'
        elsif self.class.name == 'FeedComment'
          audit_module_name = 'Comment'
        elsif self.class.name == 'SitePage'
          audit_module_name = 'Page'
        elsif self.class.name == 'DomainSetting'
          audit_module_name = 'Notification'
          audit_module_name = 'Dashboard' if(changed_attributes.has_key?("dashboard_type"))
        elsif self.class.name == 'DomainPreference'
          audit_module_name = self.audit_module_name(changed_attributes)
        elsif self.class.name == 'EcmRepository'
          audit_module_name = 'Domain'
        else
          audit_module_name = self.class.name
        end
      end
      
      def is_not_secret(secret=true)
        
        if self.class.name == 'User' || self.class.name == 'DomainProduct' || self.class.name == 'IdeaCampaign'
          secret = true
        elsif self.class.name == 'FeedComment'
          secret = (self.feed.conversation_id == nil) ? true : (self.feed.conversation.privacy_type != 'S')
        elsif self.class.name == 'SitePage'
          secret = (self.site.privacy == nil) ? true : (self.site.privacy != 'S')
        elsif self.class.name == 'Feed'
          secret = self.is_direct_msg? ? false : true
        elsif self.respond_to?(:conversation_id) && self.class.name != 'Conversation'
          secret = (self.conversation_id == nil) ? true : (self.conversation.privacy_type != 'S')
        elsif self.class.name == 'Conversation'
          secret = self.privacy_type != 'S'
        end
        secret
      end

      def get_action_name(action_type=nil)
        return get_create_action_name if action_type == 'create'
        return self.audit_action_name if self.audit_action_name.present?

        if self.class.name == 'Attachment'
          action_name = self.is_visible == false ? 'deleted permanently' : self.is_visible == true && self.is_deleted == false ? 'restore' : 'destroy'
        elsif self.class.name == 'Workflow'
          self.audit_action_name
        else
          if self.class.name == 'DomainProduct'
             action_name = 'updated'
          elsif changed_attributes.has_key?("enable_super_password") || changed_attributes.has_key?("super_password") || self.class.name == 'DomainSetting'
            if changed_attributes["enable_super_password"] == false
              action_name = 'enabled'
            elsif changed_attributes["enable_super_password"]
              action_name = 'disabled'
            else
              action_name = 'changed'
            end
          elsif self.class.name == 'Conversation'
            if changed_attributes.has_key?("conv_sub_type")
              action_name = 'Converted to Project'
            elsif changed_attributes.has_key?("created_by")
              action_name = 'Transferred Owner Rights'
            elsif changed_attributes.has_key?("is_deleted")
              action_name = changed_attributes["is_deleted"] == false ? 'Deleted' : 'Restore'
            end
          elsif self.class.name == 'Domain'
            if changed_attributes.has_key?("is_ldap_auth_enabled")
              action_name = (changed_attributes["is_ldap_auth_enabled"] == MConstants::YES) ? 'Disabled LDAP' : 'Enabled LDAP'
            elsif changed_attributes.has_key?("created_by")
              action_name = 'Transferred Owner Rights'
            elsif changed_attributes.has_key?("is_deleted")
              action_name = changed_attributes["is_deleted"] == false ? 'Deleted' : 'Restore'
            elsif changed_attributes.has_key?("storage_location")
              action_name = 'changed'
            end
          elsif changed_attributes.has_key?("enable_pin") || changed_attributes.has_key?("pin") || changed_attributes.has_key?("dashboard_type") || self.class.name == 'DomainPreference'
              if changed_attributes["enable_pin"] == false
                action_name = 'enabled'
              elsif changed_attributes["enable_pin"]
                action_name = 'disabled'
              else #if changed_attributes["pin"]
                action_name = 'changed'
              end
            elsif self.class.name == 'EcmRepository'
                action_name = 'changed'
            else
             action_name =  changed_attributes["is_deleted"] == false ? 'update' : 'restore'
          end               
        end
      end

      def get_create_action_name
        return self.audit_action_name if self.audit_action_name.present?
        return 'create'
      end

      def valid_model
        ['Conversation', 'WorkflowSetting', 'Workflow', 'DomainProduct', 'DomainSetting', 'DomainPreference', 'Domain', 'EcmRepository'].include?(self.class.name) ||
         (changed_attributes.has_key?("dashboard_type")) || 
         ( changed_attributes.has_key?("is_deleted") || 
            ( changed_attributes.has_key?("is_visible") && !(changed_attributes.has_key?('status')) )
         )
      end
      #End of custom method added made by Vikash

      def audited_changes
        all_changes = respond_to?(:changes_to_save) ? changes_to_save : changes
        if audited_options[:only].present?
          all_changes.slice(*audited_columns)
        else
          all_changes.except(*non_audited_columns)
        end
      end

      def audits_to(version = nil)
        if version == :previous
          version = if self.version
                      self.version - 1
                    else
                      previous = audits.descending.offset(1).first
                      previous ? previous.version : 1
                    end
        end
        audits.to_version(version)
      end

      # def audit_create
      #   write_audit(action: 'create', audited_changes: audited_attributes,
      #               comment: audit_comment)
      # end

      # Method defination changed by Vikash
      def audit_create
        action_name = get_action_name('create')
        write_audit(action: action_name, audited_changes: audited_attributes, comment: audit_comment,
          user_id: set_user_id, module_name: set_module_name, domain_id: set_domain_id, conversation_id: set_conversation_id, path: audit_path)
      end

      # def audit_update
      #   unless (changes = audited_changes).empty? && audit_comment.blank?
      #     write_audit(action: 'update', audited_changes: changes,
      #                 comment: audit_comment)
      #   end
      # end

      # Method defination changed by Vikash
      def audit_update      
        unless (changes = audited_changes).empty?
          if valid_model
            action_name = get_action_name
            write_audit(action: action_name, audited_changes: set_update_changes, comment: set_audit_comment,
              username: set_username, user_id: set_user_id, module_name: set_module_name, domain_id: set_domain_id, conversation_id: set_conversation_id, path: audit_path)
          end
        end
      end

      # def audit_destroy
      #   write_audit(action: 'destroy', audited_changes: audited_attributes,
      #               comment: audit_comment) unless new_record?
      # end

      # Method defination changed by Vikash
      def audit_destroy
        write_audit(action: 'deleted permanently', audited_changes: audited_attributes, comment: set_audit_comment,
          username: set_username, user_id: set_user_id, module_name: set_module_name, domain_id: set_domain_id, conversation_id: set_conversation_id, path: audit_path)
      end

      def write_audit(attrs)
        unless audit_associated_with.nil?
          attrs[:associated] = send(audit_associated_with)
          # attrs.merge!(build_associated_attr(attrs[:associated]))
        end

        self.audit_comment = nil
        run_callbacks(:audit)  { audits.create(attrs) } if auditing_enabled
      end

      def require_comment
        if auditing_enabled && audit_comment.blank?
          errors.add(:audit_comment, "Comment required before destruction")
          return false if Rails.version.start_with?('4.')
          throw :abort
        end
      end

      # Custom method added made by Vikash
      # def build_associated_attr(assoicated_object)
      #   return { association_id: assoicated_object.id, association_type: assoicated_object.class.name }
      # end

      CALLBACKS.each do |attr_name|
        alias_method "#{attr_name}_callback".to_sym, attr_name
      end

      def auditing_enabled
        self.class.auditing_enabled
      end

      def auditing_enabled=(val)
        self.class.auditing_enabled = val
      end

      def reconstruct_attributes(audits)
        attributes = {}
        audits.each { |audit| attributes.merge!(audit.new_attributes) }
        attributes
      end
    end # InstanceMethods

    module AuditedClassMethods
      # Returns an array of columns that are audited. See non_audited_columns
      def audited_columns
        @audited_columns ||= column_names - non_audited_columns
      end

      # We have to calculate this here since column_names may not be available when `audited` is called
      def non_audited_columns
        @non_audited_columns ||= audited_options[:only].present? ?
                                 column_names - audited_options[:only] :
                                 default_ignored_attributes | audited_options[:except]
      end

      def non_audited_columns=(columns)
        @audited_columns = nil # reset cached audited columns on assignment
        @non_audited_columns = columns.map(&:to_s)
      end

      # Executes the block with auditing disabled.
      #
      #   Foo.without_auditing do
      #     @foo.save
      #   end
      #
      def without_auditing
        auditing_was_enabled = auditing_enabled
        disable_auditing
        yield
      ensure
        enable_auditing if auditing_was_enabled
      end

      def disable_auditing
        self.auditing_enabled = false
      end

      def enable_auditing
        self.auditing_enabled = true
      end

      # All audit operations during the block are recorded as being
      # made by +user+. This is not model specific, the method is a
      # convenience wrapper around
      # @see Audit#as_user.
      def audit_as(user, &block)
        Audited.audit_class.as_user(user, &block)
      end

      def auditing_enabled
        Audited.store.fetch("#{table_name}_auditing_enabled", true)
      end

      def auditing_enabled=(val)
        Audited.store["#{table_name}_auditing_enabled"] = val
      end

      protected
      def default_ignored_attributes
        [primary_key, inheritance_column] + Audited.ignored_attributes
      end

      def normalize_audited_options
        audited_options[:on] = Array.wrap(audited_options[:on])
        audited_options[:on] = [:create, :update, :destroy] if audited_options[:on].empty?
        audited_options[:only] = Array.wrap(audited_options[:only]).map(&:to_s)
        audited_options[:except] = Array.wrap(audited_options[:except]).map(&:to_s)
      end
    end
  end
end
